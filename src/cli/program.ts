import { confirm, isCancel, select, text } from "@clack/prompts";
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
	interactiveEditFlow,
	interactiveExportFlow,
	interactiveGenerateFlow,
	interactiveImportFlow,
	interactiveInspectFlow,
	interactiveListFlow,
	interactivePruneFlow,
	interactiveRemoveFlow,
	interactiveRestoreFlow,
	interactiveRotateFlow,
	interactiveSignFlow,
	interactiveTrashEmptyFlow,
	interactiveTrashFlow,
	interactiveVerifyFlow,
	runInteractiveWizard,
} from "./interactive.ts";
import {
	renderExportMergeTable,
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
	yes?: boolean;
}

function shouldShowPrompts(cmdYes: boolean | undefined, globalOpts: GlobalCliOpts): boolean {
	return !cmdYes && !globalOpts.yes && !globalOpts.json && Boolean(process.stdin.isTTY);
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
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác, dùng thẳng giá trị mặc định")
		.option("--json", "Xuất kết quả dưới định dạng JSON");

	// 1. Lệnh init
	program
		.command("init")
		.description("Khởi tạo Store (jwks.json hoặc bảng Database) và thư mục lưu file .pem")
		.option("--save-profile <name>", "Lưu cấu hình hiện tại thành một profile trong .jwksctl.json")
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác")
		.action(async (cmdOpts: { saveProfile?: string; yes?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			const ctx = await resolveRuntimeContext({
				...globalOpts,
				configPath: globalOpts.config ?? globalOpts.configPath,
				tableName: globalOpts.table ?? globalOpts.tableName,
			});

			let storeUri = ctx.profile.uri;
			let keysDir = ctx.profile.keysDir;
			let saveProfile = cmdOpts.saveProfile;

			if (shouldShowPrompts(cmdOpts.yes, globalOpts)) {
				const enteredStore = await text({
					message:
						"Đường dẫn Store (file jwks.json, SQLite hoặc Database URI) [Enter dùng mặc định, 'back' để hủy]:",
					initialValue: storeUri,
					defaultValue: storeUri,
					placeholder: storeUri,
				});
				if (isCancel(enteredStore) || String(enteredStore).trim().toLowerCase() === "back") {
					return;
				}
				storeUri = String(enteredStore || storeUri).trim();

				const enteredKeysDir = await text({
					message: "Thư mục lưu file Private Key (.pem) [Enter dùng mặc định, 'back' để hủy]:",
					initialValue: keysDir,
					defaultValue: keysDir,
					placeholder: keysDir,
				});
				if (isCancel(enteredKeysDir) || String(enteredKeysDir).trim().toLowerCase() === "back") {
					return;
				}
				keysDir = String(enteredKeysDir || keysDir).trim();

				const defaultProfilePrompt = saveProfile ?? "none";
				const enteredProfile = await text({
					message:
						"Lưu cấu hình thành Profile trong .jwksctl.json [Mặc định: 'none' = không lưu, hoặc nhập tên profile]:",
					initialValue: defaultProfilePrompt,
					defaultValue: defaultProfilePrompt,
					placeholder: defaultProfilePrompt,
				});
				if (isCancel(enteredProfile) || String(enteredProfile).trim().toLowerCase() === "back") {
					return;
				}
				const profVal = String(enteredProfile || defaultProfilePrompt).trim();
				saveProfile = profVal.toLowerCase() === "none" || !profVal ? undefined : profVal;
			}

			const finalProfile = {
				...ctx.profile,
				type: detectStoreType(storeUri),
				uri: storeUri,
				keysDir,
			};
			const adapter = createStorageAdapter(finalProfile);
			const vault = new PemVault(finalProfile.keysDir);
			const manager = new KeyManagerService(adapter, vault);

			try {
				await manager.initStore();
				await mkdir(resolve(finalProfile.keysDir), { recursive: true });

				if (saveProfile) {
					const cfgPath = globalOpts.config ?? DEFAULT_CONFIG_FILE;
					const existing = (await loadConfigFile(cfgPath)) ?? {
						defaultProfile: saveProfile,
						profiles: {},
					};
					existing.profiles[saveProfile] = finalProfile;
					if (!existing.defaultProfile) {
						existing.defaultProfile = saveProfile;
					}
					await saveConfigFile(existing, cfgPath);
				}

				if (globalOpts.json) {
					console.log(
						JSON.stringify(
							{
								initialized: true,
								profile: saveProfile ?? ctx.profileName,
								storeType: finalProfile.type,
								location: manager.adapter.location,
								keysDir: resolve(finalProfile.keysDir),
							},
							null,
							2,
						),
					);
				} else {
					console.log(
						`${pc.green("✓")} Đã khởi tạo Store (${pc.cyan(finalProfile.type)}) tại: ${pc.bold(manager.adapter.location)}`,
					);
					console.log(
						`${pc.green("✓")} Thư mục Private Key (.pem): ${pc.bold(resolve(finalProfile.keysDir))}`,
					);
					if (saveProfile) {
						console.log(
							`${pc.green("✓")} Đã lưu profile "${pc.cyan(saveProfile)}" vào ${globalOpts.config ?? DEFAULT_CONFIG_FILE}`,
						);
					}
				}
			} finally {
				await adapter.close?.();
			}
		});

	// 2. Nhóm lệnh config (quản lý Profile/Context)
	const configCmd = program
		.command("config")
		.description("Quản lý các Profile kết nối trong file .jwksctl.json");

	configCmd
		.command("set [profileName]")
		.description("Thêm hoặc cập nhật một Profile kết nối")
		.option("--store <uri>", "Đường dẫn file hoặc URI kết nối Database")
		.option("--keys-dir <dir>", "Thư mục lưu file Private Key (.pem)", "./keys")
		.option("--table <name>", "Tên bảng Database", "jwks_keys")
		.option("--default", "Đặt làm profile mặc định")
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác")
		.action(
			async (
				profileNameArg: string | undefined,
				opts: {
					store?: string;
					keysDir: string;
					table: string;
					default?: boolean;
					yes?: boolean;
				},
			) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				let profileName = profileNameArg ?? "default";
				let storeUri = opts.store ?? "./jwks.json";
				let keysDir = opts.keysDir ?? "./keys";
				let tableName = opts.table ?? "jwks_keys";
				let setDefault = Boolean(opts.default);

				if (shouldShowPrompts(opts.yes, globalOpts)) {
					const pName = await text({
						message: "Tên Profile kết nối (gõ 'back' để hủy):",
						initialValue: profileName,
						defaultValue: profileName,
						placeholder: profileName,
					});
					if (isCancel(pName) || String(pName).trim().toLowerCase() === "back") {
						return;
					}
					profileName = String(pName || profileName).trim();

					const sUri = await text({
						message: "Đường dẫn file jwks.json hoặc Database URI:",
						initialValue: storeUri,
						defaultValue: storeUri,
						placeholder: storeUri,
					});
					if (isCancel(sUri) || String(sUri).trim().toLowerCase() === "back") {
						return;
					}
					storeUri = String(sUri || storeUri).trim();

					const kDir = await text({
						message: "Thư mục lưu file Private Key (.pem):",
						initialValue: keysDir,
						defaultValue: keysDir,
						placeholder: keysDir,
					});
					if (isCancel(kDir) || String(kDir).trim().toLowerCase() === "back") {
						return;
					}
					keysDir = String(kDir || keysDir).trim();

					const tName = await text({
						message: "Tên bảng Database (nếu dùng DB):",
						initialValue: tableName,
						defaultValue: tableName,
						placeholder: tableName,
					});
					if (isCancel(tName) || String(tName).trim().toLowerCase() === "back") {
						return;
					}
					tableName = String(tName || tableName).trim();

					const defConfirm = await confirm({
						message: `Đặt "${profileName}" làm profile mặc định?`,
						initialValue: opts.default ?? true,
					});
					if (isCancel(defConfirm)) {
						return;
					}
					setDefault = defConfirm;
				} else if (!opts.store) {
					throw new Error("Vui lòng truyền --store <uri> khi chạy config set với cờ -y.");
				}

				const cfgPath = globalOpts.config ?? DEFAULT_CONFIG_FILE;
				const cfg = (await loadConfigFile(cfgPath)) ?? {
					defaultProfile: profileName,
					profiles: {},
				};

				cfg.profiles[profileName] = {
					type: detectStoreType(storeUri),
					uri: storeUri,
					keysDir,
					tableName,
				};
				if (setDefault || !cfg.defaultProfile) {
					cfg.defaultProfile = profileName;
				}
				await saveConfigFile(cfg, cfgPath);

				if (globalOpts.json) {
					console.log(JSON.stringify(cfg, null, 2));
				} else {
					console.log(
						`${pc.green("✓")} Đã lưu profile "${pc.cyan(profileName)}" (${cfg.profiles[profileName]!.type}: ${storeUri}). Mặc định: ${pc.bold(cfg.defaultProfile)}`,
					);
				}
			},
		);

	configCmd
		.command("use [profileName]")
		.description("Chuyển đổi Profile mặc định")
		.option("-y, --yes", "Bỏ qua bước chọn tương tác")
		.action(async (profileNameArg: string | undefined, opts: { yes?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			const cfgPath = globalOpts.config ?? DEFAULT_CONFIG_FILE;
			const cfg = await loadConfigFile(cfgPath);
			if (!cfg || Object.keys(cfg.profiles).length === 0) {
				throw new Error(`Chưa có profile nào trong ${cfgPath}.`);
			}

			let targetProfile = profileNameArg ?? cfg.defaultProfile ?? Object.keys(cfg.profiles)[0]!;
			if (shouldShowPrompts(opts.yes, globalOpts)) {
				const chosen = await select({
					message: "Chọn Profile muốn đặt làm mặc định:",
					options: [
						...Object.entries(cfg.profiles).map(([name, p]) => ({
							value: name,
							label: `${name} (${p.type}: ${p.uri})${name === cfg.defaultProfile ? " — Đang mặc định" : ""}`,
						})),
						{ value: "__back__", label: "⬅️  Quay lại (Back)" },
					],
					initialValue: targetProfile,
				});
				if (isCancel(chosen) || chosen === "__back__") {
					return;
				}
				targetProfile = String(chosen);
			}

			if (!cfg.profiles[targetProfile]) {
				throw new Error(`Không tìm thấy profile "${targetProfile}" trong ${cfgPath}.`);
			}
			cfg.defaultProfile = targetProfile;
			await saveConfigFile(cfg, cfgPath);
			console.log(`${pc.green("✓")} Đã chuyển profile mặc định sang "${pc.cyan(targetProfile)}".`);
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
		.option("-o, --output <path>", "Thư mục hoặc đường dẫn file lưu Private Key (.pem)")
		.option(
			"-P, --output-public <path>",
			"Đường dẫn file lưu Public Key (.pem cho SPKI, .json cho JWK)",
		)
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác, tạo ngay với giá trị mặc định")
		.action(
			async (opts: {
				alg: string;
				kid?: string;
				bits: string;
				status: string;
				expiresIn?: string;
				output?: string;
				outputPublic?: string;
				yes?: boolean;
			}) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager, ctx) => {
					if (shouldShowPrompts(opts.yes, globalOpts)) {
						await interactiveGenerateFlow(manager, {
							alg: opts.alg as SigningAlgorithm,
							kid: opts.kid,
							bits: Number(opts.bits),
							status: opts.status as KeyStatus,
							expiresIn: opts.expiresIn,
							outputPem: opts.output ?? globalOpts.keysDir,
							outputPublic: opts.outputPublic,
							passphrase: ctx.passphrase,
						});
						return;
					}

					await manager.initStore();
					const { record, diff, publicFilePath } = await manager.generateKey({
						alg: opts.alg as SigningAlgorithm,
						kid: opts.kid,
						modulusLength: Number(opts.bits),
						status: opts.status as KeyStatus,
						expiresIn: opts.expiresIn,
						outputPem: opts.output,
						outputPublic: opts.outputPublic,
						passphrase: ctx.passphrase,
					});

					if (globalOpts.json) {
						console.log(JSON.stringify({ record, diff, publicFilePath }, null, 2));
					} else {
						console.log(
							`${pc.green("✓")} Đã tạo khóa mới: ${pc.bold(pc.cyan(record.kid))} (${record.alg})`,
						);
						console.log(`  Private Key (.pem): ${pc.bold(record.privateKeyPath)}`);
						if (publicFilePath) {
							console.log(`  Public Key: ${pc.bold(pc.green(publicFilePath))}`);
						}
						console.log(renderMutationDiff(diff));
					}
				});
			},
		);

	// 4. Lệnh list (Hiển thị bảng khóa kèm menu Sửa / Xóa tương tác)
	program
		.command("list")
		.alias("ls")
		.description("Liệt kê danh sách các khóa trong Store (hỗ trợ thao tác Sửa / Xóa trực tiếp)")
		.option("--status <status>", "Lọc theo trạng thái (active | passive | revoked)")
		.option("--plain", "Chỉ in bảng danh sách khóa mà không mở menu Sửa / Xóa")
		.option("-y, --yes", "Chỉ in bảng danh sách khóa mà không mở menu tương tác")
		.action(async (opts: { status?: string; plain?: boolean; yes?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				if (!opts.plain && shouldShowPrompts(opts.yes, globalOpts)) {
					await interactiveListFlow(manager, opts.status as KeyStatus | undefined);
					return;
				}

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

	// 4b. Lệnh edit (Sửa thông tin khóa)
	program
		.command("edit [kid]")
		.description(
			"Chỉnh sửa thông tin khóa (đổi kid kèm tên file .pem, đổi trạng thái status, đặt/xóa hạn dùng expiresAt)",
		)
		.option("--new-kid <kid>", "Mã định danh khóa (kid) mới")
		.option("--status <status>", "Trạng thái mới (active | passive | revoked)")
		.option("--expires-in <duration>", "Đặt thời hạn hiệu lực mới (ví dụ: 7d, 30d, 24h)")
		.option("--clear-expiry", "Xóa giới hạn thời gian hết hạn")
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác")
		.action(
			async (
				kid: string | undefined,
				opts: {
					newKid?: string;
					status?: string;
					expiresIn?: string;
					clearExpiry?: boolean;
					yes?: boolean;
				},
			) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager) => {
					if (shouldShowPrompts(opts.yes, globalOpts)) {
						await interactiveEditFlow(manager, kid, {
							newKid: opts.newKid,
							status: opts.status as KeyStatus | undefined,
							expiresIn: opts.expiresIn,
							clearExpiry: opts.clearExpiry,
						});
						return;
					}

					if (!kid) {
						throw new Error("Vui lòng truyền mã khóa <kid> cần sửa khi dùng cờ -y.");
					}

					const { record, diff } = await manager.editKey(kid, {
						newKid: opts.newKid,
						status: opts.status as KeyStatus | undefined,
						expiresIn: opts.expiresIn,
						clearExpiry: Boolean(opts.clearExpiry),
					});

					if (globalOpts.json) {
						console.log(JSON.stringify({ record, diff }, null, 2));
					} else {
						console.log(renderMutationDiff(diff));
						console.log(
							`${pc.green("✓")} Đã cập nhật khóa: ${pc.bold(pc.cyan(record.kid))} (status=${record.status}, pem=${record.privateKeyPath})`,
						);
					}
				});
			},
		);

	// 5. Lệnh inspect
	program
		.command("inspect [kid]")
		.description("Xem chi tiết một khóa, kiểm tra file .pem và hiển thị Public Key SPKI PEM")
		.option("--pem-only", "Chỉ xuất chuỗi Public Key PEM")
		.option("-y, --yes", "Bỏ qua bước chọn khóa tương tác")
		.action(async (kid: string | undefined, opts: { pemOnly?: boolean; yes?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				if (!opts.pemOnly && shouldShowPrompts(opts.yes, globalOpts)) {
					await interactiveInspectFlow(manager, kid);
					return;
				}

				let targetKid = kid;
				if (!targetKid) {
					const keys = await manager.listKeys();
					targetKid = keys.find((k) => k.status === "active")?.kid ?? keys[0]?.kid;
					if (!targetKid) {
						throw new Error("Kho lưu trữ hiện đang trống, không có khóa nào để inspect.");
					}
				}

				const info = await manager.inspectKey(targetKid);
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
		.option("-o, --output <path>", "Thư mục hoặc đường dẫn file lưu Private Key (.pem) mới")
		.option(
			"-P, --output-public <path>",
			"Đường dẫn file lưu Public Key (.pem cho SPKI, .json cho JWK)",
		)
		.option("--revoke-old", "Thu hồi (revoked) ngay lập tức khóa cũ thay vì chuyển sang passive")
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác, xoay vòng ngay với giá trị mặc định")
		.action(
			async (opts: {
				alg?: string;
				kid?: string;
				bits: string;
				gracePeriod: string;
				output?: string;
				outputPublic?: string;
				revokeOld?: boolean;
				yes?: boolean;
			}) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager, ctx) => {
					if (shouldShowPrompts(opts.yes, globalOpts)) {
						await interactiveRotateFlow(manager, {
							alg: opts.alg as SigningAlgorithm | undefined,
							kid: opts.kid,
							bits: Number(opts.bits),
							gracePeriod: opts.gracePeriod,
							outputPem: opts.output ?? globalOpts.keysDir,
							outputPublic: opts.outputPublic,
							revokeOld: Boolean(opts.revokeOld),
							passphrase: ctx.passphrase,
						});
						return;
					}

					await manager.initStore();
					const { newRecord, demotedKids, diff, publicFilePath } = await manager.rotateKeys({
						alg: opts.alg as SigningAlgorithm | undefined,
						kid: opts.kid,
						modulusLength: Number(opts.bits),
						gracePeriod: opts.gracePeriod,
						outputPem: opts.output,
						outputPublic: opts.outputPublic,
						revokeOldImmediately: Boolean(opts.revokeOld),
						passphrase: ctx.passphrase,
					});

					if (globalOpts.json) {
						console.log(JSON.stringify({ newRecord, demotedKids, diff, publicFilePath }, null, 2));
					} else {
						console.log(
							`${pc.green("✓")} Đã xoay vòng khóa thành công! Khóa active mới: ${pc.bold(pc.cyan(newRecord.kid))}`,
						);
						console.log(`  Private Key (.pem) mới: ${pc.bold(newRecord.privateKeyPath)}`);
						if (publicFilePath) {
							console.log(`  Public Key: ${pc.bold(pc.green(publicFilePath))}`);
						}
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
					if (shouldShowPrompts(opts.yes, globalOpts)) {
						await interactiveRemoveFlow(manager, parsedKids, opts.force, isPermanent);
						return;
					}

					if (parsedKids.length === 0) {
						throw new Error(
							"Vui lòng truyền ít nhất 1 mã khóa (kid) cần xóa khi dùng cờ -y / non-interactive.",
						);
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
		.option("-y, --yes", "Bỏ qua các bước hỏi xác nhận tương tác")
		.action(async (opts: { permanent?: boolean; deletePem?: boolean; yes?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			const isPermanent = Boolean(opts.permanent || opts.deletePem);
			await withManager(globalOpts, async (manager) => {
				if (shouldShowPrompts(opts.yes, globalOpts)) {
					await interactivePruneFlow(manager, isPermanent);
					return;
				}

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
					if (!opts.fromBak && shouldShowPrompts(opts.yes, globalOpts)) {
						await interactiveRestoreFlow(manager, parsedKids);
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

	// 9b. Nhóm lệnh trash (Quản lý Thùng rác)
	const trashCmd = program
		.command("trash")
		.description("Quản lý Thùng rác chứa các khóa và file .pem đã xóa (.trash)")
		.option("-y, --yes", "Chỉ hiển thị danh sách Thùng rác mà không mở menu tương tác")
		.action(async (opts: { yes?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				if (shouldShowPrompts(opts.yes, globalOpts)) {
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
		.option("-y, --yes", "Bỏ qua bước chọn và xác nhận tương tác")
		.action(async (rawKids: string[], opts: { yes?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			const parsedKids = rawKids
				.flatMap((item) => item.split(","))
				.map((s) => s.trim())
				.filter(Boolean);

			await withManager(globalOpts, async (manager) => {
				if (shouldShowPrompts(opts.yes, globalOpts)) {
					await interactiveTrashEmptyFlow(manager, parsedKids);
					return;
				}

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

	// 11. Lệnh export (Kiểm tra file tồn tại & hiện Bảng Merge chọn khóa Giữ/Bỏ)
	program
		.command("export [file]")
		.description(
			"Trích xuất bộ Public JWKS chuẩn RFC 7517 ra file (nếu file đã tồn tại sẽ hiện Bảng Merge để chọn khóa giữ/bỏ)",
		)
		.option("-o, --output <file>", "Đường dẫn file đích muốn xuất (ví dụ: ./jwks.json)")
		.option("--stdout", "Chỉ in kết quả ra màn hình (stdout) thay vì ghi ra file")
		.option("--no-passive", "Chỉ xuất các khóa đang 'active', bỏ qua các khóa 'passive'")
		.option("-f, --format <format>", "Định dạng xuất: json | pem | pub", "json")
		.option("--keep <kids>", "Danh sách kid muốn giữ lại khi Merge (cách nhau bằng dấu phẩy)")
		.option("--drop <kids>", "Danh sách kid muốn loại bỏ khi Merge (cách nhau bằng dấu phẩy)")
		.option("--overwrite", "Ghi đè toàn bộ bằng các khóa từ Store (bỏ khóa cũ chỉ có ở file đích)")
		.option("-y, --yes", "Bỏ qua các bước hỏi input & bảng chọn tương tác")
		.action(
			async (
				fileArg: string | undefined,
				opts: {
					output?: string;
					stdout?: boolean;
					passive: boolean;
					format: string;
					keep?: string;
					drop?: string;
					overwrite?: boolean;
					yes?: boolean;
				},
			) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager) => {
					const explicitFile = fileArg ?? opts.output;

					if (
						!opts.stdout &&
						!opts.keep &&
						!opts.drop &&
						!opts.overwrite &&
						shouldShowPrompts(opts.yes, globalOpts)
					) {
						await interactiveExportFlow(manager, {
							outputFile: explicitFile,
							includePassive: opts.passive,
							format: opts.format,
						});
						return;
					}

					const fmt = opts.format.toLowerCase();
					if (fmt === "pem" || fmt === "pub") {
						const payload = await manager.exportPublicJwks({
							includePassive: opts.passive,
						});
						const pemBlocks: string[] = [];
						for (const pubJwk of payload.keys) {
							const spki = await exportPublicJwkToPem(pubJwk);
							pemBlocks.push(`# KID: ${pubJwk.kid} (${pubJwk.alg})\n${spki.trim()}`);
						}
						const formattedOutput = `${pemBlocks.join("\n\n")}\n`;
						if (explicitFile) {
							const outPath = resolve(process.cwd(), explicitFile);
							await mkdir(dirname(outPath), { recursive: true });
							await Bun.write(outPath, formattedOutput);
							console.log(
								`${pc.green("✓")} Đã xuất ${payload.keys.length} Public Key PEM ra file: ${pc.bold(outPath)}`,
							);
						} else {
							process.stdout.write(formattedOutput);
						}
						return;
					}

					const cwdJwks = resolve(process.cwd(), "jwks.json");
					const storeAbs = resolve(manager.adapter.location);
					const defaultTtyFile = cwdJwks === storeAbs ? undefined : "./jwks.json";
					const targetFile =
						explicitFile ??
						(!opts.stdout && !globalOpts.json && process.stdin.isTTY ? defaultTtyFile : undefined);

					if (targetFile) {
						const outPath = resolve(process.cwd(), targetFile);
						const plan = await manager.prepareExportMergePlan(outPath, {
							includePassive: opts.passive,
						});

						let selectedKids: string[];
						if (opts.keep !== undefined) {
							selectedKids = opts.keep
								.split(",")
								.map((s) => s.trim())
								.filter(Boolean);
						} else if (opts.overwrite) {
							selectedKids = plan.candidates
								.filter((c) => c.source !== "existing_only")
								.map((c) => c.kid);
						} else {
							const dropSet = new Set(
								(opts.drop ?? "")
									.split(",")
									.map((s) => s.trim())
									.filter(Boolean),
							);
							selectedKids = plan.candidates.map((c) => c.kid).filter((kid) => !dropSet.has(kid));
						}

						const res = await manager.writeExportedJwksFile(outPath, selectedKids, plan);

						if (globalOpts.json) {
							console.log(
								JSON.stringify(
									{
										exportedCount: res.keptCount,
										keptCount: res.keptCount,
										droppedCount: res.droppedCount,
										droppedKids: res.droppedKids,
										targetFileExistsBefore: plan.targetFileExists,
										outputFile: outPath,
										candidates: plan.candidates,
									},
									null,
									2,
								),
							);
						} else {
							if (plan.targetFileExists) {
								console.log(renderExportMergeTable(plan, outPath));
								console.log(
									`${pc.green("✓")} Đã Merge & xuất ${res.keptCount} Public JWK ra file: ${pc.bold(outPath)} (Giữ: ${res.keptCount}, Bỏ: ${res.droppedCount})`,
								);
							} else {
								console.log(
									`${pc.green("✓")} Đã xuất ${res.keptCount} Public JWK chuẩn RFC 7517 ra file: ${pc.bold(outPath)}`,
								);
							}
						}
						return;
					}

					const payload = await manager.exportPublicJwks({
						includePassive: opts.passive,
					});
					process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
				});
			},
		);

	// 12. Lệnh import
	program
		.command("import [file]")
		.description("Nhập khóa có sẵn từ file Private Key (.pem PKCS#8) hoặc file JWK (.json)")
		.option("-a, --alg <alg>", "Thuật toán của khóa (bắt buộc nếu import từ file .pem)")
		.option("--kid <id>", "Mã định danh khóa (kid) tùy chỉnh")
		.option("--status <status>", "Trạng thái khóa (active | passive)", "active")
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác")
		.action(
			async (
				filePath: string | undefined,
				opts: { alg?: string; kid?: string; status: string; yes?: boolean },
			) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager, ctx) => {
					if (shouldShowPrompts(opts.yes, globalOpts)) {
						await interactiveImportFlow(manager, {
							filePath,
							alg: opts.alg as SigningAlgorithm | undefined,
							kid: opts.kid,
							status: opts.status as KeyStatus,
							passphrase: ctx.passphrase,
						});
						return;
					}

					if (!filePath) {
						throw new Error("Vui lòng truyền đường dẫn <file> cần import khi dùng cờ -y.");
					}

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
			},
		);

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
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác, ký ngay với giá trị mặc định")
		.action(
			async (opts: {
				data: string;
				kid?: string;
				expiresIn: string;
				iss?: string;
				sub?: string;
				aud?: string;
				yes?: boolean;
			}) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager, ctx) => {
					if (shouldShowPrompts(opts.yes, globalOpts)) {
						await interactiveSignFlow(manager, {
							data: opts.data,
							kid: opts.kid,
							expiresIn: opts.expiresIn,
							iss: opts.iss,
							sub: opts.sub,
							aud: opts.aud,
							passphrase: ctx.passphrase,
						});
						return;
					}

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
		.command("verify [token]")
		.description("Xác thực thử một JWT bằng bộ Public JWK trong Store")
		.option("--kid <id>", "Chỉ định kid cụ thể để verify")
		.option("--allow-expired-key", "Cho phép verify cả bằng khóa đã revoked hoặc hết hạn ân hạn")
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác")
		.action(
			async (
				token: string | undefined,
				opts: { kid?: string; allowExpiredKey?: boolean; yes?: boolean },
			) => {
				const globalOpts = program.opts<GlobalCliOpts>();
				await withManager(globalOpts, async (manager) => {
					if (shouldShowPrompts(opts.yes, globalOpts)) {
						await interactiveVerifyFlow(manager, {
							token,
							kid: opts.kid,
							allowExpiredKey: opts.allowExpiredKey,
						});
						return;
					}

					if (!token) {
						throw new Error("Vui lòng truyền chuỗi <token> cần verify khi dùng cờ -y.");
					}

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
			},
		);

	// 15. Lệnh sync
	program
		.command("sync")
		.description("Đồng bộ danh sách khóa từ Store hiện tại sang một Store hoặc Profile đích")
		.option("--to <target>", "Tên Profile đích hoặc đường dẫn/URI của Store đích")
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác")
		.action(async (opts: { to?: string; yes?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			await withManager(globalOpts, async (manager) => {
				let targetUriOrProfile = opts.to ?? "./jwks-backup.json";

				if (shouldShowPrompts(opts.yes, globalOpts)) {
					const enteredTo = await text({
						message:
							"Nhập tên Profile đích hoặc đường dẫn/URI của Store đích cần đồng bộ tới (gõ 'back' để hủy):",
						initialValue: targetUriOrProfile,
						defaultValue: targetUriOrProfile,
						placeholder: targetUriOrProfile,
					});
					if (isCancel(enteredTo) || String(enteredTo).trim().toLowerCase() === "back") {
						return;
					}
					targetUriOrProfile = String(enteredTo || targetUriOrProfile).trim();

					const ok = await confirm({
						message: `Xác nhận đồng bộ danh sách khóa từ ${manager.adapter.location} → ${targetUriOrProfile}?`,
						initialValue: true,
					});
					if (isCancel(ok) || !ok) {
						return;
					}
				} else if (!opts.to) {
					throw new Error("Vui lòng truyền --to <target> khi chạy sync với cờ -y.");
				}

				const cfg = await loadConfigFile(globalOpts.config);
				const targetProfile = cfg?.profiles?.[targetUriOrProfile] ?? {
					type: detectStoreType(targetUriOrProfile),
					uri: targetUriOrProfile,
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
		.option("-y, --yes", "Bỏ qua các bước hỏi input tương tác, chạy server ngay với cổng mặc định")
		.action(async (opts: { port: string; host: string; yes?: boolean }) => {
			const globalOpts = program.opts<GlobalCliOpts>();
			let host = opts.host ?? "127.0.0.1";
			let port = opts.port ?? "8080";

			if (shouldShowPrompts(opts.yes, globalOpts)) {
				const enteredHost = await text({
					message: "Địa chỉ Host lắng nghe HTTP (Enter dùng mặc định, gõ 'back' để hủy):",
					initialValue: host,
					defaultValue: host,
					placeholder: host,
				});
				if (isCancel(enteredHost) || String(enteredHost).trim().toLowerCase() === "back") {
					return;
				}
				host = String(enteredHost || host).trim();

				const enteredPort = await text({
					message: "Cổng HTTP (Port) [Enter dùng mặc định, gõ 'back' để hủy]:",
					initialValue: port,
					defaultValue: port,
					placeholder: port,
				});
				if (isCancel(enteredPort) || String(enteredPort).trim().toLowerCase() === "back") {
					return;
				}
				port = String(enteredPort || port).trim();
			}

			const ctx = await resolveRuntimeContext(globalOpts);
			const adapter = createStorageAdapter(ctx.profile);
			const vault = new PemVault(ctx.profile.keysDir);
			const manager = new KeyManagerService(adapter, vault);
			await manager.initStore();

			const server = Bun.serve({
				hostname: host,
				port: Number(port),
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
