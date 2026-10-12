import { Command } from "commander";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import pc from "picocolors";
import {
	createStorageAdapter,
	DEFAULT_CONFIG_FILE,
	detectStoreType,
	loadConfigFile,
	resolveRuntimeContext,
	saveConfigFile,
	type RuntimeOptions,
} from "../config/loader.ts";
import { exportPublicJwkToPem } from "../core/crypto.ts";
import { KeyManagerService } from "../core/key-manager.ts";
import { PemVault } from "../core/pem-vault.ts";
import type { KeyStatus, SigningAlgorithm } from "../core/types.ts";
import {
	interactiveRemoveFlow,
	interactiveRestoreFlow,
	interactiveTrashFlow,
	runInteractiveWizard,
} from "./interactive.ts";
import {
	renderInspectReport,
	renderIntegrityReport,
	renderKeyTable,
	renderMutationDiff,
	renderTrashTable,
} from "./output.ts";

interface GlobalCliOpts extends RuntimeOptions {
	config?: string;
	table?: string;
	json?: boolean;
}

async function withManager<T>(
	globalOpts: GlobalCliOpts,
	fn: (
		manager: KeyManagerService,
		ctx: Awaited<ReturnType<typeof resolveRuntimeContext>>,
	) => Promise<T>,
): Promise<T> {
	const ctx = await resolveRuntimeContext({
		...globalOpts,
		configPath: globalOpts.config ?? globalOpts.configPath,
		tableName: globalOpts.table ?? globalOpts.tableName,
	});
	const adapter = createStorageAdapter(ctx.profile);
	const vault = new PemVault(ctx.profile.keysDir);
	const manager = new KeyManagerService(adapter, vault);
	try {
		return await fn(manager, ctx);
	} finally {
		await adapter.close?.();
	}
}

export function buildCliProgram(): Command {
	const program = new Command();

	program
		.name("jwksctl")
		.description(
			"Công cụ CLI quản lý vòng đời JWKS (File JSON & Database) an toàn, tách biệt Public JWK và Private Key (.pem)",
		)
		.version("1.0.0")
		.option("-s, --store <uri>", "Đường dẫn file jwks.json, file SQLite hoặc Database URI")
		.option("-p, --profile <name>", "Tên profile cấu hình trong .jwksctl.json")
		.option("-k, --keys-dir <dir>", "Thư mục lưu trữ các file Private Key (.pem)")
		.option("-t, --table <name>", "Tên bảng trong Database (mặc định: jwks_keys)")
		.option("--passphrase <secret>", "Passphrase mã hóa/giải mã AES-256-GCM cho file .pem")
		.option("--config <path>", "Đường dẫn tới file cấu hình .jwksctl.json", DEFAULT_CONFIG_FILE)
		.option("--json", "Xuất kết quả dưới định dạng JSON");

	// 1. Lệnh init
	program
		.command("init")
		.description("Khởi tạo Store (jwks.json hoặc bảng Database) và thư mục lưu file .pem")
		.option("--save-profile <name>", "Lưu cấu hình hiện tại thành một profile trong .jwksctl.json")
		.action(async (cmdOpts: { saveProfile?: string }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager, ctx) => {
				await manager.initStore();
				await mkdir(resolve(ctx.profile.keysDir), { recursive: true });

				if (cmdOpts.saveProfile) {
					const cfgPath = globalOpts.config ?? DEFAULT_CONFIG_FILE;
					const existing = (await loadConfigFile(cfgPath)) ?? {
						defaultProfile: cmdOpts.saveProfile,
						profiles: {},
					};
					existing.profiles[cmdOpts.saveProfile] = ctx.profile;
					if (!existing.defaultProfile) {
						existing.defaultProfile = cmdOpts.saveProfile;
					}
					await saveConfigFile(existing, cfgPath);
				}

				if (globalOpts.json) {
					console.log(
						JSON.stringify(
							{
								initialized: true,
								profile: cmdOpts.saveProfile ?? ctx.profileName,
								storeType: ctx.profile.type,
								location: manager.adapter.location,
								keysDir: resolve(ctx.profile.keysDir),
							},
							null,
							2,
						),
					);
				} else {
					console.log(
						`${pc.green("✓")} Đã khởi tạo Store (${pc.cyan(ctx.profile.type)}) tại: ${pc.bold(manager.adapter.location)}`,
					);
					console.log(
						`${pc.green("✓")} Thư mục Private Key (.pem): ${pc.bold(resolve(ctx.profile.keysDir))}`,
					);
					if (cmdOpts.saveProfile) {
						console.log(
							`${pc.green("✓")} Đã lưu profile "${pc.cyan(cmdOpts.saveProfile)}" vào ${globalOpts.config ?? DEFAULT_CONFIG_FILE}`,
						);
					}
				}
			});
		});

	// 2. Nhóm lệnh config (quản lý Profile/Context)
	const configCmd = program
		.command("config")
		.description("Quản lý các Profile kết nối trong file .jwksctl.json");

	configCmd
		.command("set <profileName>")
		.description("Thêm hoặc cập nhật một Profile kết nối")
		.requiredOption("--store <uri>", "Đường dẫn file hoặc URI kết nối Database")
		.option("--keys-dir <dir>", "Thư mục lưu file Private Key (.pem)", "./keys")
		.option("--table <name>", "Tên bảng Database", "jwks_keys")
		.option("--default", "Đặt làm profile mặc định")
		.action(
			async (
				profileName: string,
				opts: { store: string; keysDir: string; table: string; default?: boolean },
			) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				const cfgPath = globalOpts.config ?? DEFAULT_CONFIG_FILE;
				const cfg = (await loadConfigFile(cfgPath)) ?? {
					defaultProfile: profileName,
					profiles: {},
				};

				cfg.profiles[profileName] = {
					type: detectStoreType(opts.store),
					uri: opts.store,
					keysDir: opts.keysDir,
					tableName: opts.table,
				};
				if (opts.default || !cfg.defaultProfile) {
					cfg.defaultProfile = profileName;
				}
				await saveConfigFile(cfg, cfgPath);

				if (globalOpts.json) {
					console.log(JSON.stringify(cfg, null, 2));
				} else {
					console.log(
						`${pc.green("✓")} Đã lưu profile "${pc.cyan(profileName)}" (${cfg.profiles[profileName]!.type}: ${opts.store}). Mặc định: ${pc.bold(cfg.defaultProfile)}`,
					);
				}
			},
		);

	configCmd
		.command("use <profileName>")
		.description("Chuyển đổi Profile mặc định")
		.action(async (profileName: string) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			const cfgPath = globalOpts.config ?? DEFAULT_CONFIG_FILE;
			const cfg = await loadConfigFile(cfgPath);
			if (!cfg || !cfg.profiles[profileName]) {
				throw new Error(`Không tìm thấy profile "${profileName}" trong ${cfgPath}.`);
			}
			cfg.defaultProfile = profileName;
			await saveConfigFile(cfg, cfgPath);
			console.log(`${pc.green("✓")} Đã chuyển profile mặc định sang "${pc.cyan(profileName)}".`);
		});

	configCmd
		.command("list")
		.description("Liệt kê các Profile trong .jwksctl.json")
		.action(async () => {
			const globalOpts = program.opts<GlobalCliOpts>();
			const cfgPath = globalOpts.config ?? DEFAULT_CONFIG_FILE;
			const cfg = await loadConfigFile(cfgPath);
			if (globalOpts.json) {
				console.log(JSON.stringify(cfg ?? { defaultProfile: null, profiles: {} }, null, 2));
				return;
			}
			if (!cfg || Object.keys(cfg.profiles).length === 0) {
				console.log(pc.dim("Chưa có profile nào được cấu hình trong .jwksctl.json."));
				return;
			}
			for (const [name, p] of Object.entries(cfg.profiles)) {
				const mark = name === cfg.defaultProfile ? pc.green("● (default)") : "  ";
				console.log(
					`${mark} ${pc.bold(name)}: type=${pc.cyan(p.type)}, uri=${p.uri}, keysDir=${p.keysDir ?? "./keys"}`,
				);
			}
		});

	// 3. Lệnh generate
	program
		.command("generate")
		.alias("gen")
		.description("Tạo cặp khóa mới (lưu Private Key ra file .pem và lưu Public JWK vào Store)")
		.option("-a, --alg <alg>", "Thuật toán ký (RS256, ES256, EdDSA...)", "RS256")
		.option("--kid <id>", "Mã định danh khóa (kid) tùy chỉnh")
		.option("--bits <number>", "Độ dài khóa RSA (2048, 3072, 4096)", "2048")
		.option("--status <status>", "Trạng thái ban đầu (active | passive)", "active")
		.option("--expires-in <duration>", "Thời hạn hiệu lực (ví dụ: 30d, 24h)")
		.action(
			async (opts: {
				alg: string;
				kid?: string;
				bits: string;
				status: string;
				expiresIn?: string;
			}) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager, ctx) => {
					await manager.initStore();
					const { record, diff } = await manager.generateKey({
						alg: opts.alg as SigningAlgorithm,
						kid: opts.kid,
						modulusLength: Number(opts.bits),
						status: opts.status as KeyStatus,
						expiresIn: opts.expiresIn,
						passphrase: ctx.passphrase,
					});

					if (globalOpts.json) {
						console.log(JSON.stringify({ record, diff }, null, 2));
					} else {
						console.log(
							`${pc.green("✓")} Đã tạo khóa mới: ${pc.bold(pc.cyan(record.kid))} (${record.alg})`,
						);
						console.log(`  Private Key (.pem): ${pc.bold(record.privateKeyPath)}`);
						console.log(renderMutationDiff(diff));
					}
				});
			},
		);

	// 4. Lệnh list
	program
		.command("list")
		.alias("ls")
		.description("Liệt kê danh sách các khóa trong Store")
		.option("--status <status>", "Lọc theo trạng thái (active | passive | revoked)")
		.action(async (opts: { status?: string }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				const records = await manager.listKeys({
					status: opts.status as KeyStatus | undefined,
				});

				if (globalOpts.json) {
					console.log(JSON.stringify({ keys: records }, null, 2));
					return;
				}

				const pemMap = new Map<string, boolean>();
				for (const rec of records) {
					pemMap.set(rec.kid, await manager.vault.exists(rec.privateKeyPath));
				}
				console.log(renderKeyTable(records, pemMap));
			});
		});

	// 5. Lệnh inspect
	program
		.command("inspect <kid>")
		.description("Xem chi tiết một khóa, kiểm tra file .pem và hiển thị Public Key SPKI PEM")
		.option("--pem-only", "Chỉ xuất chuỗi Public Key PEM")
		.action(async (kid: string, opts: { pemOnly?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				const info = await manager.inspectKey(kid);
				if (opts.pemOnly) {
					process.stdout.write(info.publicPem);
					return;
				}
				if (globalOpts.json) {
					console.log(JSON.stringify(info, null, 2));
					return;
				}
				console.log(renderInspectReport(info));
			});
		});

	// 6. Lệnh rotate
	program
		.command("rotate")
		.description(
			"Xoay vòng khóa: Tạo khóa active mới và chuyển khóa active cũ sang passive (có thời gian ân hạn)",
		)
		.option("-a, --alg <alg>", "Thuật toán cho khóa mới (mặc định kế thừa khóa active hiện tại)")
		.option("--kid <id>", "Mã định danh (kid) cho khóa mới")
		.option("--bits <number>", "Độ dài khóa RSA (mặc định: 2048)", "2048")
		.option("-g, --grace-period <duration>", "Thời gian ân hạn cho khóa cũ (ví dụ: 7d, 24h)", "7d")
		.option("--revoke-old", "Thu hồi (revoked) ngay lập tức khóa cũ thay vì chuyển sang passive")
		.action(
			async (opts: {
				alg?: string;
				kid?: string;
				bits: string;
				gracePeriod: string;
				revokeOld?: boolean;
			}) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager, ctx) => {
					await manager.initStore();
					const { newRecord, demotedKids, diff } = await manager.rotateKeys({
						alg: opts.alg as SigningAlgorithm | undefined,
						kid: opts.kid,
						modulusLength: Number(opts.bits),
						gracePeriod: opts.gracePeriod,
						revokeOldImmediately: Boolean(opts.revokeOld),
						passphrase: ctx.passphrase,
					});

					if (globalOpts.json) {
						console.log(JSON.stringify({ newRecord, demotedKids, diff }, null, 2));
					} else {
						console.log(
							`${pc.green("✓")} Đã xoay vòng khóa thành công! Khóa active mới: ${pc.bold(pc.cyan(newRecord.kid))}`,
						);
						if (demotedKids.length > 0) {
							console.log(
								`  Khóa cũ chuyển sang ${opts.revokeOld ? pc.red("revoked") : pc.yellow(`passive (ân hạn ${opts.gracePeriod})`)}: ${demotedKids.join(", ")}`,
							);
						}
						console.log(renderMutationDiff(diff));
					}
				});
			},
		);

	// 7. Lệnh remove (Hỗ trợ xóa 1 hoặc nhiều khóa cùng lúc + đưa vào Thùng rác .trash)
	program
		.command("remove [kids...]")
		.alias("rm")
		.description(
			"Xóa an toàn 1 hoặc nhiều khóa (mặc định đưa khóa & file .pem vào Thùng rác .trash để có thể restore)",
		)
		.option("-f, --force", "Cho phép xóa cả khóa đang ở trạng thái 'active'")
		.option("--permanent", "Xóa vĩnh viễn không qua Thùng rác (xóa hẳn file .pem trên ổ đĩa)")
		.option(
			"--delete-pem",
			"Tương đương --permanent (xóa vĩnh viễn file Private Key .pem trên đĩa)",
		)
		.option("-y, --yes", "Bỏ qua bước hỏi xác nhận tương tác (dùng cho CI/CD)")
		.action(
			async (
				rawKids: string[],
				opts: { force?: boolean; permanent?: boolean; deletePem?: boolean; yes?: boolean },
			) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				const parsedKids = rawKids
					.flatMap((item) => item.split(","))
					.map((s) => s.trim())
					.filter(Boolean);
				const isPermanent = Boolean(opts.permanent || opts.deletePem);

				await withManager(globalOpts, async (manager) => {
					if (parsedKids.length === 0 || (!opts.yes && !globalOpts.json && process.stdin.isTTY)) {
						if (parsedKids.length === 0 && !process.stdin.isTTY) {
							throw new Error(
								"Vui lòng truyền ít nhất 1 mã khóa (kid) cần xóa khi chạy ở chế độ non-interactive.",
							);
						}
						await interactiveRemoveFlow(manager, parsedKids, opts.force, isPermanent);
						return;
					}

					const { diff, trashedItems, deletedPemPaths } = await manager.removeKeys(parsedKids, {
						force: Boolean(opts.force),
						permanent: isPermanent,
					});

					if (globalOpts.json) {
						console.log(
							JSON.stringify(
								{ diff, trashedItems, deletedPemPaths, permanent: isPermanent },
								null,
								2,
							),
						);
					} else {
						console.log(renderMutationDiff(diff));
						if (isPermanent) {
							console.log(
								`${pc.green("✓")} Đã xóa vĩnh viễn ${diff.removed.length} khóa và ${deletedPemPaths.length} file .pem. Giữ nguyên 100% ${diff.afterCount} khóa còn lại.`,
							);
						} else {
							console.log(
								`${pc.green("✓")} Đã chuyển ${trashedItems.length} khóa & file .pem vào Thùng rác (${pc.cyan(manager.vault.trashDir)}). Giữ nguyên 100% ${diff.afterCount} khóa còn lại.`,
							);
						}
					}
				});
			},
		);

	// 8. Lệnh prune
	program
		.command("prune")
		.description("Dọn dẹp tự động các khóa đã bị thu hồi (revoked) hoặc passive đã hết hạn")
		.option("--permanent", "Xóa vĩnh viễn các file Private Key (.pem) thay vì đưa vào Thùng rác")
		.option("--delete-pem", "Tương đương --permanent")
		.action(async (opts: { permanent?: boolean; deletePem?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			const isPermanent = Boolean(opts.permanent || opts.deletePem);
			await withManager(globalOpts, async (manager) => {
				const result = await manager.pruneKeys({
					permanent: isPermanent,
				});

				if (globalOpts.json) {
					console.log(JSON.stringify(result, null, 2));
					return;
				}

				if (result.prunedKids.length === 0) {
					console.log(pc.dim("Không có khóa nào ở trạng thái revoked hoặc hết hạn cần dọn dẹp."));
					return;
				}

				console.log(renderMutationDiff(result.diff));
				console.log(
					`${pc.green("✓")} Đã dọn dẹp ${result.prunedKids.length} khóa (${isPermanent ? "xóa vĩnh viễn" : `chuyển vào ${manager.vault.trashDir}`}): ${result.prunedKids.join(", ")}`,
				);
			});
		});

	// 9. Lệnh restore (Khôi phục cả khóa JWK lẫn file .pem từ Thùng rác .trash hoặc file .bak)
	program
		.command("restore [kids...]")
		.description(
			"Khôi phục khóa JWK và file Private Key (.pem) từ Thùng rác (.trash) hoặc từ bản sao lưu (.bak)",
		)
		.option("--from-bak", "Khôi phục từ file jwks.json.bak kết hợp lấy lại file .pem từ Thùng rác")
		.option("--all", "Khôi phục toàn bộ các khóa đang có trong Thùng rác")
		.option("-y, --yes", "Bỏ qua giao diện chọn tương tác")
		.action(
			async (rawKids: string[], opts: { fromBak?: boolean; all?: boolean; yes?: boolean }) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				const parsedKids = rawKids
					.flatMap((item) => item.split(","))
					.map((s) => s.trim())
					.filter(Boolean);

				await withManager(globalOpts, async (manager) => {
					if (
						!opts.fromBak &&
						!opts.all &&
						parsedKids.length === 0 &&
						!opts.yes &&
						!globalOpts.json &&
						process.stdin.isTTY
					) {
						await interactiveRestoreFlow(manager);
						return;
					}

					const res = await manager.restoreKeys({
						kids: parsedKids,
						fromBak: Boolean(opts.fromBak),
					});
					const allKeysAfter = await manager.listKeys();

					if (globalOpts.json) {
						console.log(
							JSON.stringify(
								{
									mode: res.mode,
									restoredCount: allKeysAfter.length,
									restoredFromTrashCount: res.restoredRecords.length,
									restoredPemPaths: res.restoredPemPaths,
									keys: res.restoredRecords,
								},
								null,
								2,
							),
						);
					} else {
						console.log(
							`${pc.green("✓")} Đã khôi phục thành công ${res.restoredRecords.length} khóa (${res.mode === "trash" ? "từ Thùng rác .trash" : "từ bản sao lưu .bak"}) vào ${manager.adapter.location}.`,
						);
						if (res.restoredPemPaths.length > 0) {
							console.log(
								`  ${pc.green("✓")} Đã trả lại ${res.restoredPemPaths.length} file Private Key (.pem) về thư mục gốc: ${pc.bold(res.restoredPemPaths.join(", "))}`,
							);
						}
					}
				});
			},
		);

	// 9b. Nhóm lệnh trash (Quản lý Thùng rác ./keys/.trash)
	const trashCmd = program
		.command("trash")
		.description("Quản lý Thùng rác chứa các khóa và file .pem đã xóa (./keys/.trash)")
		.action(async () => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				if (!globalOpts.json && process.stdin.isTTY) {
					await interactiveTrashFlow(manager);
					return;
				}
				const items = await manager.listTrash();
				if (globalOpts.json) {
					console.log(JSON.stringify({ trashDir: manager.vault.trashDir, items }, null, 2));
				} else {
					console.log(renderTrashTable(items));
				}
			});
		});

	trashCmd
		.command("list")
		.alias("ls")
		.description("Liệt kê các khóa và file .pem đang nằm trong Thùng rác")
		.action(async () => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				const items = await manager.listTrash();
				if (globalOpts.json) {
					console.log(JSON.stringify({ trashDir: manager.vault.trashDir, items }, null, 2));
				} else {
					console.log(renderTrashTable(items));
				}
			});
		});

	trashCmd
		.command("empty [kids...]")
		.description("Dọn sạch vĩnh viễn toàn bộ (hoặc một số kid) trong Thùng rác")
		.action(async (rawKids: string[]) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			const parsedKids = rawKids
				.flatMap((item) => item.split(","))
				.map((s) => s.trim())
				.filter(Boolean);

			await withManager(globalOpts, async (manager) => {
				const deletedCount = await manager.emptyTrash(
					parsedKids.length > 0 ? parsedKids : undefined,
				);
				if (globalOpts.json) {
					console.log(JSON.stringify({ emptiedCount: deletedCount }, null, 2));
				} else {
					console.log(
						`${pc.green("✓")} Đã xóa vĩnh viễn ${deletedCount} mục khỏi Thùng rác (${manager.vault.trashDir}).`,
					);
				}
			});
		});

	// 10. Lệnh check (Kiểm tra toàn vẹn)
	program
		.command("check")
		.description("Kiểm tra tính toàn vẹn của jwks.json/DB và sự tồn tại của các file .pem")
		.action(async () => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				const report = await manager.checkIntegrity();
				if (globalOpts.json) {
					console.log(JSON.stringify(report, null, 2));
				} else {
					console.log(renderIntegrityReport(report, manager.adapter.location));
				}
				if (!report.valid) {
					process.exitCode = 1;
				}
			});
		});

	// 11. Lệnh export
	program
		.command("export")
		.description(
			"Trích xuất bộ Public JWKS chuẩn RFC 7517 thuần khiết (loại bỏ toàn bộ metadata nội bộ)",
		)
		.option("-o, --output <file>", "Ghi kết quả ra file thay vì in ra màn hình (stdout)")
		.option("--no-passive", "Chỉ xuất các khóa đang 'active', bỏ qua các khóa 'passive'")
		.option("-f, --format <format>", "Định dạng xuất: json | pem", "json")
		.action(async (opts: { output?: string; passive: boolean; format: string }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				const payload = await manager.exportPublicJwks({
					includePassive: opts.passive,
				});

				let formattedOutput: string;
				if (opts.format.toLowerCase() === "pem") {
					const pemBlocks: string[] = [];
					for (const pubJwk of payload.keys) {
						const spki = await exportPublicJwkToPem(pubJwk);
						pemBlocks.push(`# KID: ${pubJwk.kid} (${pubJwk.alg})\n${spki.trim()}`);
					}
					formattedOutput = `${pemBlocks.join("\n\n")}\n`;
				} else {
					formattedOutput = `${JSON.stringify(payload, null, 2)}\n`;
				}

				if (opts.output) {
					const outPath = resolve(opts.output);
					await mkdir(dirname(outPath), { recursive: true });
					await Bun.write(outPath, formattedOutput);
					if (!globalOpts.json) {
						console.log(
							`${pc.green("✓")} Đã xuất ${payload.keys.length} Public JWK chuẩn RFC 7517 ra file: ${pc.bold(outPath)}`,
						);
					} else {
						console.log(
							JSON.stringify({ exportedCount: payload.keys.length, outputFile: outPath }, null, 2),
						);
					}
				} else {
					process.stdout.write(formattedOutput);
				}
			});
		});

	// 12. Lệnh import
	program
		.command("import <file>")
		.description("Nhập khóa có sẵn từ file Private Key (.pem PKCS#8) hoặc file JWK (.json)")
		.option("-a, --alg <alg>", "Thuật toán của khóa (bắt buộc nếu import từ file .pem)")
		.option("--kid <id>", "Mã định danh khóa (kid) tùy chỉnh")
		.option("--status <status>", "Trạng thái khóa (active | passive)", "active")
		.action(async (filePath: string, opts: { alg?: string; kid?: string; status: string }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager, ctx) => {
				await manager.initStore();
				const file = Bun.file(resolve(filePath));
				if (!(await file.exists())) {
					throw new Error(`Không tìm thấy file cần import tại: ${filePath}`);
				}
				const rawContent = await file.text();
				const { record, diff } = await manager.importKey({
					rawContent,
					alg: opts.alg as SigningAlgorithm | undefined,
					kid: opts.kid,
					status: opts.status as KeyStatus,
					passphrase: ctx.passphrase,
				});

				if (globalOpts.json) {
					console.log(JSON.stringify({ record, diff }, null, 2));
				} else {
					console.log(
						`${pc.green("✓")} Đã import thành công khóa: ${pc.bold(pc.cyan(record.kid))} (${record.alg})`,
					);
					console.log(`  Đã lưu Private Key (.pem) tại: ${pc.bold(record.privateKeyPath)}`);
					console.log(renderMutationDiff(diff));
				}
			});
		});

	// 13. Lệnh sign
	program
		.command("sign")
		.description("Ký thử một JWT bằng khóa trong Store (đọc Private Key từ privateKeyPath)")
		.option("-d, --data <json>", "Payload JSON của JWT", '{"sub":"test-user"}')
		.option("--kid <id>", "Chỉ định kid của khóa dùng để ký (mặc định dùng khóa active mới nhất)")
		.option("-e, --expires-in <duration>", "Thời hạn token (ví dụ: 1h, 15m, 7d)", "1h")
		.option("--iss <issuer>", "Trường iss (Issuer)")
		.option("--sub <subject>", "Trường sub (Subject)")
		.option("--aud <audience>", "Trường aud (Audience)")
		.action(
			async (opts: {
				data: string;
				kid?: string;
				expiresIn: string;
				iss?: string;
				sub?: string;
				aud?: string;
			}) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager, ctx) => {
					const payload = JSON.parse(opts.data) as Record<string, unknown>;
					const { token, usedKey } = await manager.signJwt({
						payload,
						kid: opts.kid,
						expiresIn: opts.expiresIn,
						issuer: opts.iss,
						subject: opts.sub,
						audience: opts.aud,
						passphrase: ctx.passphrase,
					});

					if (globalOpts.json) {
						console.log(JSON.stringify({ token, kid: usedKey.kid, alg: usedKey.alg }, null, 2));
					} else {
						console.log(token);
					}
				});
			},
		);

	// 14. Lệnh verify
	program
		.command("verify <token>")
		.description("Xác thực thử một JWT bằng bộ Public JWK trong Store")
		.option("--kid <id>", "Chỉ định kid cụ thể để verify")
		.option("--allow-expired-key", "Cho phép verify cả bằng khóa đã revoked hoặc hết hạn ân hạn")
		.action(async (token: string, opts: { kid?: string; allowExpiredKey?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				const result = await manager.verifyJwt(token, {
					kid: opts.kid,
					allowRevokedOrExpiredKey: Boolean(opts.allowExpiredKey),
				});

				if (globalOpts.json) {
					console.log(JSON.stringify(result, null, 2));
				} else {
					console.log(
						`${pc.green("✓ JWT Hợp lệ!")} Xác thực bởi khóa: ${pc.bold(pc.cyan(result.matchedKey.kid))} (${result.matchedKey.alg}, status=${result.matchedKey.status})`,
					);
					console.log(pc.bold("Header:"), JSON.stringify(result.protectedHeader));
					console.log(pc.bold("Payload:"), JSON.stringify(result.payload, null, 2));
				}
			});
		});

	// 15. Lệnh sync
	program
		.command("sync")
		.description("Đồng bộ danh sách khóa từ Store hiện tại sang một Store hoặc Profile đích")
		.requiredOption("--to <target>", "Tên Profile đích hoặc đường dẫn/URI của Store đích")
		.action(async (opts: { to: string }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				const cfg = await loadConfigFile(globalOpts.config);
				const targetProfile = cfg?.profiles?.[opts.to] ?? {
					type: detectStoreType(opts.to),
					uri: opts.to,
					tableName: globalOpts.tableName ?? "jwks_keys",
				};

				const targetAdapter = createStorageAdapter(targetProfile);
				try {
					const result = await manager.syncTo(targetAdapter);
					if (globalOpts.json) {
						console.log(
							JSON.stringify(
								{
									from: manager.adapter.location,
									to: targetAdapter.location,
									...result,
								},
								null,
								2,
							),
						);
					} else {
						console.log(
							`${pc.green("✓")} Đã đồng bộ từ ${pc.bold(manager.adapter.location)} → ${pc.bold(targetAdapter.location)} (Thêm mới: ${result.addedCount}, Cập nhật: ${result.updatedCount})`,
						);
					}
				} finally {
					await targetAdapter.close?.();
				}
			});
		});

	// 16. Lệnh serve
	program
		.command("serve")
		.description("Mở nhanh HTTP Server phục vụ /.well-known/jwks.json trực tiếp từ Store")
		.option("--port <number>", "Cổng lắng nghe HTTP", "8080")
		.option("--host <host>", "Địa chỉ host lắng nghe", "127.0.0.1")
		.action(async (opts: { port: string; host: string }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			const ctx = await resolveRuntimeContext(globalOpts);
			const adapter = createStorageAdapter(ctx.profile);
			const vault = new PemVault(ctx.profile.keysDir);
			const manager = new KeyManagerService(adapter, vault);
			await manager.initStore();

			const server = Bun.serve({
				hostname: opts.host,
				port: Number(opts.port),
				async fetch(req) {
					const url = new URL(req.url);
					if (
						req.method === "GET" &&
						(url.pathname === "/.well-known/jwks.json" || url.pathname === "/jwks.json")
					) {
						const payload = await manager.exportPublicJwks();
						return Response.json(payload, {
							headers: {
								"Cache-Control": "public, max-age=60",
								"Access-Control-Allow-Origin": "*",
							},
						});
					}
					if (req.method === "GET" && url.pathname === "/health") {
						const report = await manager.checkIntegrity();
						return Response.json(report, { status: report.valid ? 200 : 503 });
					}
					return Response.json({ error: "Not Found" }, { status: 404 });
				},
			});

			console.log(
				`${pc.green("●")} JWKS Server đang chạy tại: ${pc.bold(pc.cyan(`http://${server.hostname}:${server.port}/.well-known/jwks.json`))}`,
			);
			console.log(`  Nguồn dữ liệu: ${adapter.location} (${adapter.kind})`);
			console.log(pc.dim("  Nhấn Ctrl+C để dừng server."));
		});

	// 17. Lệnh interactive
	program
		.command("interactive")
		.alias("ui")
		.description("Mở giao diện điều khiển tương tác từng bước (Interactive Wizard)")
		.action(async () => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager, ctx) => {
				await runInteractiveWizard(manager, ctx.passphrase);
			});
		});

	return program;
}
