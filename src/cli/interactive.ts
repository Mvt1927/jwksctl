import { CANCEL_SYMBOL, MultiSelectPrompt } from "@clack/core";
import {
	confirm,
	intro,
	isCancel,
	log,
	note,
	outro,
	password,
	select,
	spinner,
	text,
} from "@clack/prompts";
import { resolve } from "node:path";
import pc from "picocolors";
import type { KeyManagerService } from "../core/key-manager.ts";
import { SUPPORTED_ALGORITHMS, type KeyStatus, type SigningAlgorithm } from "../core/types.ts";
import {
	renderExportMergeTable,
	renderInspectReport,
	renderIntegrityReport,
	renderKeyTable,
	renderMutationDiff,
	renderTrashTable,
} from "./output.ts";

const BACK_VALUE = "__back__";

interface StyledOption {
	value: string;
	label: string;
	hint?: string;
}

/**
 * Bảng chọn nhiều khóa (Checkbox) tùy chỉnh kèm dòng "⬅️ Quay lại (Back)":
 * - Khóa ĐƯỢC CHỌN: Hiển thị màu Xanh lá đậm + Gạch dưới (underline) + nhãn [✓ ĐÃ CHỌN] nổi bật.
 * - Khóa CHƯA CHỌN: Hiển thị màu Xám mờ (dim) + nhãn [ ] để phân biệt rõ ràng ngay lập tức.
 * - Dòng cuối "⬅️ Quay lại (Back)": Nhấn Space hoặc Enter tại dòng này (hoặc phím Esc) để quay về menu trước.
 */
async function styledMultiselect(opts: {
	message: string;
	options: StyledOption[];
	initialValues?: string[];
	required?: boolean;
	selectedTag?: string;
	unselectedTag?: string;
}): Promise<string[] | symbol> {
	const selTag = opts.selectedTag ?? "ĐÃ CHỌN";
	const unselTag = opts.unselectedTag ?? "BỎ QUA";
	const fullOptions: StyledOption[] = [
		...opts.options,
		{
			value: BACK_VALUE,
			label: "⬅️  Quay lại (Back)",
			hint: "Nhấn Enter hoặc Space tại đây để quay về màn hình trước",
		},
	];

	let lastCursor = 0;

	const prompt = new MultiSelectPrompt<StyledOption>({
		options: fullOptions,
		initialValues: opts.initialValues ? [...opts.initialValues] : [],
		required: false,
		validate(val) {
			const focusedOpt = fullOptions[lastCursor];
			if (focusedOpt?.value === BACK_VALUE || val?.includes(BACK_VALUE)) {
				return undefined;
			}
			const realSelected = (val ?? []).filter((v) => v !== BACK_VALUE);
			if ((opts.required ?? true) && realSelected.length === 0) {
				return "Vui lòng tích chọn ít nhất 1 khóa (Nhấn Space để chọn, hoặc chọn '⬅️ Quay lại' để thoát).";
			}
			return undefined;
		},
		render() {
			lastCursor = this.cursor;
			const bar = pc.cyan("│");
			const grayBar = pc.gray("│");
			const selectedList = (this.value ?? []).filter((v) => v !== BACK_VALUE);

			const headerSymbol =
				this.state === "submit"
					? pc.green("◇")
					: this.state === "cancel"
						? pc.red("■")
						: this.state === "error"
							? pc.yellow("▲")
							: pc.cyan("◆");

			const titleLine = `${grayBar}\n${headerSymbol}  ${pc.bold(opts.message)}`;

			if (this.state === "submit") {
				if (
					this.options[this.cursor]?.value === BACK_VALUE ||
					(this.value ?? []).includes(BACK_VALUE)
				) {
					return `${titleLine}\n${grayBar}  ${pc.dim("⬅️  Đã quay lại")}`;
				}
				const chosen = this.options
					.filter((o) => o.value !== BACK_VALUE && selectedList.includes(o.value))
					.map((o) => pc.green(pc.underline(o.value)))
					.join(pc.dim(", "));
				return `${titleLine}\n${grayBar}  ${chosen || pc.dim("(Không chọn khóa nào)")}`;
			}

			if (this.state === "cancel") {
				return `${titleLine}\n${grayBar}  ${pc.dim("⬅️  Đã quay lại")}`;
			}

			const optionLines = this.options.map((opt, idx) => {
				const isFocused = idx === this.cursor;
				const pointer = isFocused ? pc.cyan(pc.bold("❯")) : " ";

				if (opt.value === BACK_VALUE) {
					const backLabel = isFocused
						? pc.yellow(pc.bold(pc.underline(opt.label)))
						: pc.dim(opt.label);
					const hintStr = isFocused && opt.hint ? ` ${pc.dim(`(${opt.hint})`)}` : "";
					return `${bar}  ${pointer} ${backLabel}${hintStr}`;
				}

				const isSelected = selectedList.includes(opt.value);
				if (isSelected) {
					const badge = pc.green(pc.bold(`[✓ ${selTag}]`));
					const styledLabel = isFocused
						? pc.green(pc.bold(pc.underline(opt.label)))
						: pc.green(pc.underline(opt.label));
					const hintStr = opt.hint ? ` ${pc.dim(`(${opt.hint})`)}` : "";
					return `${bar}  ${pointer} ${badge} ${styledLabel}${hintStr}`;
				}

				const badge = isFocused ? pc.yellow(`[  ${unselTag}]`) : pc.dim(`[  ${unselTag}]`);
				const styledLabel = isFocused ? pc.white(opt.label) : pc.dim(opt.label);
				const hintStr = isFocused && opt.hint ? ` ${pc.dim(`(${opt.hint})`)}` : "";
				return `${bar}  ${pointer} ${badge} ${styledLabel}${hintStr}`;
			});

			const footerHelp = `${bar}  ${pc.dim("↑/↓: Di chuyển  •  Space: Chọn/Bỏ chọn  •  A: Chọn tất cả  •  Enter: Xác nhận")}`;
			const bottomBar =
				this.state === "error" ? `${pc.yellow("└")}  ${pc.yellow(this.error)}` : pc.cyan("└");

			return [titleLine, ...optionLines, footerHelp, bottomBar].join("\n");
		},
	});

	const rawResult = await prompt.prompt();
	if (isCancel(rawResult)) {
		return CANCEL_SYMBOL;
	}
	const arr = Array.isArray(rawResult) ? rawResult : [];
	if (prompt.options[prompt.cursor]?.value === BACK_VALUE || arr.includes(BACK_VALUE)) {
		return CANCEL_SYMBOL;
	}
	return arr.filter((v) => v !== BACK_VALUE);
}

/**
 * Hỏi người dùng chọn 1 hoặc nhiều khóa để xóa an toàn (mặc định đưa khóa + file .pem vào Thùng rác .trash).
 */
export async function interactiveRemoveFlow(
	manager: KeyManagerService,
	preselectedKids?: string[],
	forceOption?: boolean,
	permanentOption?: boolean,
): Promise<void> {
	const allKeys = await manager.listKeys();
	if (allKeys.length === 0) {
		log.warn("Kho lưu trữ hiện đang trống, không có khóa nào để xóa.");
		return;
	}

	const nonActiveKids = allKeys.filter((k) => k.status !== "active").map((k) => k.kid);
	const defaultSelected =
		preselectedKids && preselectedKids.length > 0
			? preselectedKids
			: nonActiveKids.length > 0
				? nonActiveKids
				: [allKeys[0]!.kid];

	const picked = await styledMultiselect({
		message: "Chọn 1 hoặc nhiều khóa cần xóa (Dùng phím Space để tích chọn, Enter để xác nhận):",
		options: allKeys.map((k) => ({
			value: k.kid,
			label: `${k.kid} [${k.alg}] — status: ${k.status}`,
			hint: k.status === "active" ? "ĐANG ACTIVE (Cẩn trọng!)" : `pem: ${k.privateKeyPath}`,
		})),
		initialValues: defaultSelected,
		required: true,
		selectedTag: "XÓA",
		unselectedTag: "GIỮ",
	});

	if (isCancel(picked)) {
		return;
	}
	const selectedKids = picked as string[];

	const hasActiveSelected = allKeys.some(
		(k) => selectedKids.includes(k.kid) && k.status === "active",
	);
	let allowForce = Boolean(forceOption);

	if (hasActiveSelected && !allowForce) {
		log.warn(
			pc.red("CẢNH BÁO: Bạn đang chọn xóa khóa có trạng thái 'active' (đang dùng để ký JWT)!"),
		);
		const confirmActive = await confirm({
			message: "Bạn có thực sự chắc chắn muốn cưỡng bức xóa khóa đang 'active' này không?",
			initialValue: false,
		});
		if (isCancel(confirmActive) || !confirmActive) {
			log.info("Đã quay lại để bảo vệ khóa đang active.");
			return;
		}
		allowForce = true;
	}

	const diffPreview = await manager.previewRemoveKeys(selectedKids, {
		force: allowForce,
	});
	note(renderMutationDiff(diffPreview), "Xem trước thay đổi (SafeMutationGuard)");

	const mode = await select({
		message: `Chọn chế độ xóa cho ${selectedKids.length} khóa đã chọn (còn lại ${diffPreview.afterCount} khóa giữ nguyên 100%):`,
		options: [
			{
				value: "trash",
				label: `♻️  Đưa khóa & file .pem vào Thùng rác (${manager.vault.trashDir}) — Mặc định`,
				hint: "Có thể khôi phục lại cả khóa lẫn file .pem bằng lệnh restore",
			},
			{
				value: "permanent",
				label: "🔥 Xóa vĩnh viễn (Xóa hẳn khỏi Store và xóa vĩnh viễn file .pem trên đĩa)",
				hint: "Không thể khôi phục lại file .pem",
			},
			{
				value: BACK_VALUE,
				label: "⬅️  Quay lại (Back)",
			},
		],
		initialValue: permanentOption ? "permanent" : "trash",
	});
	if (isCancel(mode) || mode === BACK_VALUE) {
		return;
	}
	const isPermanent = mode === "permanent";

	const confirmDelete = await confirm({
		message: isPermanent
			? `Xác nhận XÓA VĨNH VIỄN ${selectedKids.length} khóa và file .pem tương ứng?`
			: `Xác nhận chuyển ${selectedKids.length} khóa và file .pem vào Thùng rác?`,
		initialValue: !isPermanent,
	});
	if (isCancel(confirmDelete) || !confirmDelete) {
		return;
	}

	const { diff, trashedItems, deletedPemPaths } = await manager.removeKeys(selectedKids, {
		force: allowForce,
		permanent: isPermanent,
	});

	if (isPermanent) {
		log.success(
			`Đã xóa vĩnh viễn ${diff.removed.length} khóa và ${deletedPemPaths.length} file .pem. Bảo toàn nguyên vẹn ${diff.afterCount} khóa còn lại.`,
		);
	} else {
		log.success(
			`Đã chuyển ${trashedItems.length} khóa (cùng file .pem) vào Thùng rác (${pc.cyan(manager.vault.trashDir)}). Bảo toàn nguyên vẹn ${diff.afterCount} khóa còn lại.`,
		);
		log.info(
			`Gợi ý: Chạy ${pc.cyan("jwksctl restore")} bất kỳ lúc nào để khôi phục lại cả khóa và file .pem.`,
		);
	}
}

/**
 * Luồng tương tác chọn 1 hoặc nhiều khóa trong Thùng rác (.trash) để khôi phục cả JWK và file .pem.
 */
export async function interactiveRestoreFlow(
	manager: KeyManagerService,
	preselectedKids?: string[],
): Promise<void> {
	const trashItems = await manager.listTrash();
	if (trashItems.length === 0) {
		log.warn(`Thùng rác (${manager.vault.trashDir}) hiện đang trống.`);
		if (manager.adapter.restoreBackup) {
			const askBak = await confirm({
				message: "Bạn có muốn thử khôi phục từ file sao lưu .bak gần nhất không?",
				initialValue: true,
			});
			if (!isCancel(askBak) && askBak) {
				const res = await manager.restoreKeys({ fromBak: true });
				log.success(
					`Đã khôi phục ${res.restoredRecords.length} khóa từ bản sao lưu (.bak) và ${res.restoredPemPaths.length} file .pem.`,
				);
			}
		}
		return;
	}

	const defaultSelected =
		preselectedKids && preselectedKids.length > 0
			? preselectedKids
			: trashItems.map((item) => item.record.kid);

	const picked = await styledMultiselect({
		message:
			"Chọn 1 hoặc nhiều khóa trong Thùng rác cần khôi phục (Space để chọn/bỏ, Enter để xác nhận):",
		options: trashItems.map((item) => ({
			value: item.record.kid,
			label: `${item.record.kid} [${item.record.alg}] — status cũ: ${item.record.status}`,
			hint: `Xóa lúc: ${item.deletedAt.slice(0, 19).replace("T", " ")} | pem: ${
				item.trashPemPath
					? `✓ Có file trong .trash → trả về ${item.record.privateKeyPath}`
					: "✗ Không có file .pem"
			}`,
		})),
		initialValues: defaultSelected,
		required: true,
		selectedTag: "KHÔI PHỤC",
		unselectedTag: "BỎ QUA   ",
	});

	if (isCancel(picked)) {
		return;
	}

	const selectedKids = picked as string[];
	const { restoredRecords, restoredPemPaths } = await manager.restoreKeys({
		kids: selectedKids,
	});

	log.success(
		`Đã khôi phục thành công ${restoredRecords.length} khóa vào Store (${manager.adapter.location})!`,
	);
	if (restoredPemPaths.length > 0) {
		log.info(
			`Đã trả lại ${restoredPemPaths.length} file Private Key (.pem) về thư mục gốc: ${restoredPemPaths.join(", ")}`,
		);
	}
}

/**
 * Luồng quản lý Thùng rác tương tác (xem danh sách, khôi phục hoặc dọn sạch vĩnh viễn).
 */
export async function interactiveTrashFlow(manager: KeyManagerService): Promise<void> {
	while (true) {
		const trashItems = await manager.listTrash();
		console.log("\n" + renderTrashTable(trashItems) + "\n");

		if (trashItems.length === 0) {
			return;
		}

		const subAction = await select({
			message: `Thùng rác hiện có ${trashItems.length} khóa. Bạn muốn làm gì?`,
			options: [
				{ value: "restore", label: "♻️  Chọn khóa để khôi phục lại vào Store & trả lại file .pem" },
				{
					value: "empty",
					label: "🔥 Dọn sạch Thùng rác (Xóa vĩnh viễn các file .pem trong .trash)",
				},
				{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
			],
			initialValue: "restore",
		});

		if (isCancel(subAction) || subAction === BACK_VALUE) {
			return;
		}

		if (subAction === "restore") {
			await interactiveRestoreFlow(manager);
			continue;
		}

		if (subAction === "empty") {
			await interactiveTrashEmptyFlow(manager);
			return;
		}
	}
}

/**
 * Luồng chọn khóa trong Thùng rác để xóa vĩnh viễn.
 */
export async function interactiveTrashEmptyFlow(
	manager: KeyManagerService,
	preselectedKids?: string[],
): Promise<void> {
	const trashItems = await manager.listTrash();
	if (trashItems.length === 0) {
		log.info(`Thùng rác (${manager.vault.trashDir}) hiện đang trống.`);
		return;
	}

	const defaultSelected =
		preselectedKids && preselectedKids.length > 0
			? preselectedKids
			: trashItems.map((i) => i.record.kid);

	const picked = await styledMultiselect({
		message:
			"Chọn các mục trong Thùng rác muốn XÓA VĨNH VIỄN (Space để chọn/bỏ, Enter để xác nhận):",
		options: trashItems.map((item) => ({
			value: item.record.kid,
			label: `${item.record.kid} [${item.record.alg}]`,
			hint: `Xóa lúc: ${item.deletedAt.slice(0, 19).replace("T", " ")}`,
		})),
		initialValues: defaultSelected,
		required: true,
		selectedTag: "XÓA HẲN",
		unselectedTag: "GIỮ LẠI",
	});
	if (isCancel(picked)) {
		return;
	}
	const selectedKids = picked as string[];

	const confirmEmpty = await confirm({
		message: `Bạn có chắc chắn muốn XÓA VĨNH VIỄN ${selectedKids.length} mục đã chọn khỏi Thùng rác không?`,
		initialValue: true,
	});
	if (isCancel(confirmEmpty) || !confirmEmpty) {
		return;
	}

	const count = await manager.emptyTrash(selectedKids);
	log.success(`Đã xóa vĩnh viễn ${count} mục khỏi Thùng rác (${manager.vault.trashDir}).`);
}

/**
 * Luồng dọn dẹp tự động các khóa đã thu hồi (revoked) hoặc hết hạn (prune) với giá trị mặc định.
 */
export async function interactivePruneFlow(
	manager: KeyManagerService,
	permanentDefault = false,
): Promise<void> {
	const mode = await select({
		message: "Chọn chế độ dọn dẹp các khóa đã thu hồi (revoked) hoặc hết hạn:",
		options: [
			{
				value: "trash",
				label: `♻️  Chuyển khóa & file .pem vào Thùng rác (${manager.vault.trashDir}) — Mặc định`,
			},
			{
				value: "permanent",
				label: "🔥 Xóa vĩnh viễn (Xóa hẳn file .pem trên ổ đĩa)",
			},
			{
				value: BACK_VALUE,
				label: "⬅️  Quay lại (Back)",
			},
		],
		initialValue: permanentDefault ? "permanent" : "trash",
	});
	if (isCancel(mode) || mode === BACK_VALUE) {
		return;
	}

	const isPermanent = mode === "permanent";
	const confirmPrune = await confirm({
		message: `Xác nhận dọn dẹp các khóa hết hạn / đã thu hồi (${isPermanent ? "Xóa vĩnh viễn" : "Đưa vào Thùng rác"})?`,
		initialValue: true,
	});
	if (isCancel(confirmPrune) || !confirmPrune) {
		return;
	}

	const result = await manager.pruneKeys({ permanent: isPermanent });
	if (result.prunedKids.length === 0) {
		log.info("Không có khóa nào ở trạng thái revoked hoặc hết hạn cần dọn dẹp.");
		return;
	}
	note(renderMutationDiff(result.diff), "Kết quả Prune");
	log.success(
		`Đã dọn dẹp ${result.prunedKids.length} khóa (${isPermanent ? "xóa vĩnh viễn" : `chuyển vào ${manager.vault.trashDir}`}): ${result.prunedKids.join(", ")}`,
	);
}

/**
 * Luồng tạo khóa mới (generate) luôn hiển thị đầy đủ input với giá trị mặc định.
 */
export async function interactiveGenerateFlow(
	manager: KeyManagerService,
	defaults: {
		alg?: SigningAlgorithm;
		kid?: string;
		bits?: number;
		status?: KeyStatus;
		expiresIn?: string;
		outputPem?: string;
		outputPublic?: string;
		passphrase?: string;
	} = {},
): Promise<void> {
	const alg = await select({
		message: "Chọn thuật toán ký (alg):",
		options: [
			...SUPPORTED_ALGORITHMS.map((a) => ({
				value: a,
				label: a === (defaults.alg ?? "RS256") ? `${a} (Mặc định)` : a,
				hint:
					a === "EdDSA"
						? "Ed25519 (Nhanh, khóa nhỏ, hiện đại)"
						: a === "ES256"
							? "ECDSA P-256 (Phổ biến, gọn nhẹ)"
							: a === "RS256"
								? "RSA 2048-bit (Tương thích rộng nhất)"
								: undefined,
			})),
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: (defaults.alg ?? "RS256") as string,
	});
	if (isCancel(alg) || alg === BACK_VALUE) {
		return;
	}

	let modulusLength = defaults.bits ?? 2048;
	if (String(alg).startsWith("RS") || String(alg).startsWith("PS")) {
		const bitsChoice = await select({
			message: "Chọn độ dài khóa RSA (bits):",
			options: [
				{ value: "2048", label: "2048 bits (Mặc định — Chuẩn tốc độ & bảo mật)" },
				{ value: "3072", label: "3072 bits (Bảo mật cao)" },
				{ value: "4096", label: "4096 bits (Bảo mật tối đa)" },
				{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
			],
			initialValue: String(defaults.bits ?? 2048),
		});
		if (isCancel(bitsChoice) || bitsChoice === BACK_VALUE) {
			return;
		}
		modulusLength = Number(bitsChoice);
	}

	const defaultKidVal = defaults.kid ?? "auto";
	const customKid = await text({
		message:
			"Mã định danh khóa (kid) [Mặc định: 'auto' = tự sinh theo RFC 7638, gõ 'back' để quay lại]:",
		initialValue: defaultKidVal,
		defaultValue: defaultKidVal,
		placeholder: defaultKidVal,
	});
	if (isCancel(customKid) || String(customKid).trim().toLowerCase() === "back") {
		return;
	}
	const resolvedKid =
		!customKid || String(customKid).trim().toLowerCase() === "auto"
			? undefined
			: String(customKid).trim();

	const defaultPemTarget = defaults.outputPem ?? "./keys";
	const pemLocationInput = await text({
		message:
			"Vị trí lưu file cặp khóa (.pem — chứa cả Public & Private Key) [Mặc định: ./keys, gõ '.' để lưu tại thư mục hiện tại, 'back' để quay lại]:",
		initialValue: defaultPemTarget,
		defaultValue: defaultPemTarget,
		placeholder: defaultPemTarget,
	});
	if (isCancel(pemLocationInput) || String(pemLocationInput).trim().toLowerCase() === "back") {
		return;
	}
	const resolvedOutputPem = String(pemLocationInput || defaultPemTarget).trim();

	const statusChoice = await select({
		message: "Trạng thái ban đầu của khóa (status):",
		options: [
			{ value: "active", label: "● active — Dùng để ký JWT mới & xác thực (Mặc định)" },
			{ value: "passive", label: "◐ passive — Chỉ dùng xác thực Public Key" },
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: (defaults.status ?? "active") as string,
	});
	if (isCancel(statusChoice) || statusChoice === BACK_VALUE) {
		return;
	}

	const defaultExpVal = defaults.expiresIn ?? "none";
	const expInput = await text({
		message:
			"Thời hạn hiệu lực (expiresIn) [Mặc định: 'none' = không giới hạn, hoặc nhập 30d, 24h, 'back' để quay lại]:",
		initialValue: defaultExpVal,
		defaultValue: defaultExpVal,
		placeholder: defaultExpVal,
	});
	if (isCancel(expInput) || String(expInput).trim().toLowerCase() === "back") {
		return;
	}
	const resolvedExpiresIn =
		!expInput || String(expInput).trim().toLowerCase() === "none"
			? undefined
			: String(expInput).trim();

	const wantEncrypt = await confirm({
		message: "Bạn có muốn mã hóa file Private Key (.pem) bằng AES-256-GCM không?",
		initialValue: Boolean(defaults.passphrase),
	});
	if (isCancel(wantEncrypt)) {
		return;
	}

	let passphrase = defaults.passphrase;
	if (wantEncrypt && !passphrase) {
		const entered = await password({
			message: "Nhập passphrase để mã hóa file Private Key (.pem):",
			validate: (val) => (!val || val.length < 4 ? "Passphrase cần ít nhất 4 ký tự" : undefined),
		});
		if (isCancel(entered)) {
			return;
		}
		passphrase = entered;
	}

	const s = spinner();
	s.start(`Đang sinh cặp khóa ${alg}...`);
	await manager.initStore();
	const { record, diff, publicFilePath } = await manager.generateKey({
		alg: alg as SigningAlgorithm,
		kid: resolvedKid,
		modulusLength,
		status: statusChoice as KeyStatus,
		expiresIn: resolvedExpiresIn,
		outputPem: resolvedOutputPem,
		outputPublic: (defaults as { outputPublic?: string }).outputPublic,
		passphrase: wantEncrypt ? passphrase : undefined,
	});
	s.stop(`Đã tạo thành công khóa "${pc.cyan(record.kid)}" (${record.alg})!`);
	log.info(
		`File cặp khóa (.pem — chứa cả Public SPKI & Private Key): ${pc.bold(record.privateKeyPath)}`,
	);
	if (publicFilePath) {
		log.info(
			`Public Key (${publicFilePath.endsWith(".json") ? "JWK JSON" : "SPKI PEM"}): ${pc.bold(pc.green(publicFilePath))}`,
		);
	}
	note(renderMutationDiff(diff), "Kết quả cập nhật Store");
}

/**
 * Luồng xoay vòng khóa (rotate) luôn hiển thị input với giá trị mặc định.
 */
export async function interactiveRotateFlow(
	manager: KeyManagerService,
	defaults: {
		alg?: SigningAlgorithm;
		kid?: string;
		bits?: number;
		gracePeriod?: string;
		revokeOld?: boolean;
		outputPem?: string;
		outputPublic?: string;
		passphrase?: string;
	} = {},
): Promise<void> {
	const algChoice = await select({
		message: "Chọn thuật toán cho khóa active mới:",
		options: [
			{
				value: "inherit",
				label: "🔄 Kế thừa thuật toán từ khóa active hiện tại (Mặc định)",
				hint: "Tự động dùng RS256 nếu chưa có khóa active",
			},
			...SUPPORTED_ALGORITHMS.map((a) => ({
				value: a,
				label: a,
			})),
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: (defaults.alg ?? "inherit") as string,
	});
	if (isCancel(algChoice) || algChoice === BACK_VALUE) {
		return;
	}

	const defaultGrace = defaults.gracePeriod ?? "7d";
	const grace = await text({
		message:
			"Thời gian ân hạn (Grace Period) cho khóa cũ ở trạng thái 'passive' (gõ 'back' để quay lại):",
		initialValue: defaultGrace,
		defaultValue: defaultGrace,
		placeholder: defaultGrace,
	});
	if (isCancel(grace) || String(grace).trim().toLowerCase() === "back") {
		return;
	}

	const defaultKidVal = defaults.kid ?? "auto";
	const kidInput = await text({
		message: "Mã định danh (kid) cho khóa mới [Mặc định: 'auto' = tự sinh, gõ 'back' để quay lại]:",
		initialValue: defaultKidVal,
		defaultValue: defaultKidVal,
		placeholder: defaultKidVal,
	});
	if (isCancel(kidInput) || String(kidInput).trim().toLowerCase() === "back") {
		return;
	}
	const resolvedKid =
		!kidInput || String(kidInput).trim().toLowerCase() === "auto"
			? undefined
			: String(kidInput).trim();

	const defaultPemTarget = defaults.outputPem ?? "./keys";
	const pemLocationInput = await text({
		message:
			"Vị trí lưu file cặp khóa mới (.pem — chứa cả Public & Private Key) [Mặc định: ./keys, gõ 'back' để quay lại]:",
		initialValue: defaultPemTarget,
		defaultValue: defaultPemTarget,
		placeholder: defaultPemTarget,
	});
	if (isCancel(pemLocationInput) || String(pemLocationInput).trim().toLowerCase() === "back") {
		return;
	}
	const resolvedOutputPem = String(pemLocationInput || defaultPemTarget).trim();

	const oldKeyAction = await select({
		message: "Cách xử lý khóa active cũ:",
		options: [
			{
				value: "passive",
				label: `◐ Chuyển sang 'passive' với thời gian ân hạn ${String(grace || defaultGrace)} (Mặc định)`,
			},
			{
				value: "revoke",
				label: "✕ Thu hồi ('revoked') khóa cũ ngay lập tức",
			},
			{
				value: BACK_VALUE,
				label: "⬅️  Quay lại (Back)",
			},
		],
		initialValue: defaults.revokeOld ? "revoke" : "passive",
	});
	if (isCancel(oldKeyAction) || oldKeyAction === BACK_VALUE) {
		return;
	}

	const s = spinner();
	s.start("Đang xoay vòng khóa...");
	await manager.initStore();
	const { newRecord, demotedKids, diff, publicFilePath } = await manager.rotateKeys({
		alg: algChoice === "inherit" ? undefined : (algChoice as SigningAlgorithm),
		kid: resolvedKid,
		modulusLength: defaults.bits ?? 2048,
		gracePeriod: String(grace || defaultGrace).trim(),
		revokeOldImmediately: oldKeyAction === "revoke",
		outputPem: resolvedOutputPem,
		outputPublic: (defaults as { outputPublic?: string }).outputPublic,
		passphrase: defaults.passphrase,
	});
	s.stop(
		`Đã xoay vòng khóa thành công! Khóa active mới: ${pc.green(newRecord.kid)} (${oldKeyAction === "revoke" ? "Thu hồi" : "Chuyển sang passive"}: ${demotedKids.join(", ") || "không có"})`,
	);
	log.info(
		`File cặp khóa (.pem — chứa cả Public SPKI & Private Key) mới: ${pc.bold(newRecord.privateKeyPath)}`,
	);
	if (publicFilePath) {
		log.info(
			`Public Key (${publicFilePath.endsWith(".json") ? "JWK JSON" : "SPKI PEM"}): ${pc.bold(pc.green(publicFilePath))}`,
		);
	}
	note(renderMutationDiff(diff), "Kết quả Rotate");
}

/**
 * Luồng xem chi tiết khóa (inspect) với giá trị mặc định.
 */
export async function interactiveInspectFlow(
	manager: KeyManagerService,
	preselectedKid?: string,
): Promise<void> {
	const keys = await manager.listKeys();
	if (keys.length === 0) {
		log.warn("Chưa có khóa nào trong Store.");
		return;
	}
	const defaultKid =
		preselectedKid && keys.some((k) => k.kid === preselectedKid)
			? preselectedKid
			: (keys.find((k) => k.status === "active")?.kid ?? keys[0]!.kid);

	const chosenKid = await select({
		message: "Chọn khóa cần xem chi tiết (Inspect):",
		options: [
			...keys.map((k) => ({
				value: k.kid,
				label: `${k.kid} [${k.alg}] — status: ${k.status}${k.kid === defaultKid ? " (Mặc định)" : ""}`,
			})),
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: defaultKid,
	});
	if (isCancel(chosenKid) || chosenKid === BACK_VALUE) {
		return;
	}
	const info = await manager.inspectKey(String(chosenKid));
	note(renderInspectReport(info), `Chi tiết khóa ${info.record.kid}`);
}

/**
 * Luồng xuất Public JWKS ra file đích:
 * - Luôn hiển thị các bước hỏi đường dẫn file, định dạng, có lấy khóa passive không với giá trị mặc định.
 * - Hiển thị danh sách chọn khóa (và Bảng đối chiếu Merge nếu file đích đã tồn tại).
 */
export async function interactiveExportFlow(
	manager: KeyManagerService,
	options: { outputFile?: string; includePassive?: boolean; format?: string } = {},
): Promise<void> {
	const cwdJwksPath = resolve(process.cwd(), "jwks.json");
	const storeAbsPath = resolve(manager.adapter.location);
	const defaultTarget =
		options.outputFile ?? (cwdJwksPath === storeAbsPath ? "./public-jwks.json" : "./jwks.json");

	const entered = await text({
		message:
			"Đường dẫn file đích muốn xuất Public JWKS (Enter để dùng mặc định, gõ 'stdout' để in màn hình, 'back' để quay lại):",
		initialValue: defaultTarget,
		defaultValue: defaultTarget,
		placeholder: defaultTarget,
	});
	if (isCancel(entered)) {
		return;
	}
	const targetFile = String(entered || defaultTarget).trim();
	if (targetFile.toLowerCase() === "back") {
		return;
	}

	const formatChoice = await select({
		message: "Chọn định dạng xuất (format):",
		options: [
			{ value: "json", label: "📄 JSON chuẩn RFC 7517 (jwks.json) — Mặc định" },
			{ value: "pub", label: "🔑 File .pub / PEM (Chuỗi Public Key SPKI PEM)" },
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: (
			options.format ??
			(targetFile.endsWith(".pub") || targetFile.endsWith(".pem") ? "pub" : "json")
		).toLowerCase(),
	});
	if (isCancel(formatChoice) || formatChoice === BACK_VALUE) {
		return;
	}

	const includePassive = await confirm({
		message: "Bao gồm cả các khóa đang ở trạng thái 'passive' (trong thời gian ân hạn)?",
		initialValue: options.includePassive ?? true,
	});
	if (isCancel(includePassive)) {
		return;
	}

	if (formatChoice === "pub" || formatChoice === "pem") {
		const payload = await manager.exportPublicJwks({ includePassive });
		const { exportPublicJwkToPem } = await import("../core/crypto.ts");
		const pemBlocks: string[] = [];
		for (const pubJwk of payload.keys) {
			const spki = await exportPublicJwkToPem(pubJwk);
			pemBlocks.push(`# KID: ${pubJwk.kid} (${pubJwk.alg})\n${spki.trim()}`);
		}
		const formattedOutput = `${pemBlocks.join("\n\n")}\n`;
		if (targetFile.toLowerCase() === "stdout" || targetFile === "-") {
			process.stdout.write(formattedOutput);
		} else {
			let outPath = resolve(process.cwd(), targetFile);
			if (outPath.endsWith(".json") && formatChoice === "pub") {
				outPath = outPath.replace(/\.json$/, ".pub");
			}
			const { mkdir } = await import("node:fs/promises");
			const { dirname } = await import("node:path");
			await mkdir(dirname(outPath), { recursive: true });
			await Bun.write(outPath, formattedOutput);
			log.success(`Đã xuất ${payload.keys.length} Public Key (.pub) ra file: ${pc.bold(outPath)}`);
		}
		return;
	}

	if (targetFile.toLowerCase() === "stdout" || targetFile === "-") {
		const exported = await manager.exportPublicJwks({
			includePassive,
		});
		console.log(JSON.stringify(exported, null, 2));
		return;
	}

	const absOutPath = resolve(process.cwd(), targetFile);
	if (absOutPath === storeAbsPath) {
		log.warn(
			pc.yellow(
				`Đường dẫn ${absOutPath} trùng với file Store gốc của jwksctl. Vui lòng chọn đường dẫn file xuất khác (ví dụ ./public-jwks.json hoặc đứng tại thư mục dự án cần xuất) để không làm mất metadata privateKeyPath của Store gốc.`,
			),
		);
		return;
	}

	const plan = await manager.prepareExportMergePlan(absOutPath, {
		includePassive,
	});

	if (plan.targetFileExists) {
		note(
			renderExportMergeTable(plan, absOutPath),
			"Phát hiện file đã tồn tại — Bảng đối chiếu Merge JWKS",
		);
	}

	if (plan.candidates.length === 0) {
		log.warn("Không có khóa nào trong cả file đích lẫn Store để xuất.");
		return;
	}

	const pickedKids = await styledMultiselect({
		message: plan.targetFileExists
			? "Chọn các khóa muốn GIỮ LẠI trong file xuất ra (Dùng phím Space để Giữ/Bỏ, Enter để lưu):"
			: "Chọn các khóa muốn XUẤT ra file mới (Mặc định chọn tất cả — Dùng Space để Giữ/Bỏ, Enter để lưu):",
		options: plan.candidates.map((c) => ({
			value: c.kid,
			label: `${c.kid} [${c.jwk.alg} / ${c.jwk.kty}]`,
			hint:
				c.source === "new_from_store"
					? "+ Mới từ jwksctl Store"
					: c.source === "both"
						? "~ Trùng KID (Cập nhật bản chuẩn từ Store)"
						: "○ Chỉ có ở file đích hiện tại (Bỏ tích nếu muốn loại bỏ)",
		})),
		initialValues: plan.candidates.map((c) => c.kid),
		required: false,
		selectedTag: "GIỮ LẠI",
		unselectedTag: "LOẠI BỎ",
	});

	if (isCancel(pickedKids)) {
		return;
	}

	const selectedKids = pickedKids as string[];
	const res = await manager.writeExportedJwksFile(absOutPath, selectedKids, plan);

	if (plan.targetFileExists) {
		log.success(
			`Đã Merge & xuất thành công ra file: ${pc.bold(absOutPath)} (Giữ lại: ${pc.green(String(res.keptCount))} khóa | Loại bỏ: ${pc.yellow(String(res.droppedCount))} khóa${
				res.droppedKids.length > 0 ? ` [${res.droppedKids.join(", ")}]` : ""
			})`,
		);
	} else {
		log.success(
			`Đã tạo mới và xuất ${res.keptCount} Public JWK chuẩn RFC 7517 ra file: ${pc.bold(absOutPath)}`,
		);
	}
}

/**
 * Luồng chỉnh sửa thông tin khóa tương tác (đổi kid kèm file .pem, đổi status, cập nhật hạn dùng expiresAt).
 */
export async function interactiveEditFlow(
	manager: KeyManagerService,
	preselectedKid?: string,
	defaults: {
		newKid?: string;
		status?: KeyStatus;
		expiresIn?: string;
		clearExpiry?: boolean;
	} = {},
): Promise<void> {
	const allKeys = await manager.listKeys();
	if (allKeys.length === 0) {
		log.warn("Kho lưu trữ hiện đang trống, không có khóa nào để sửa.");
		return;
	}

	const defaultTargetKid =
		preselectedKid && allKeys.some((k) => k.kid === preselectedKid)
			? preselectedKid
			: allKeys[0]!.kid;

	const chosen = await select({
		message: "Chọn khóa cần chỉnh sửa (Edit):",
		options: [
			...allKeys.map((k) => ({
				value: k.kid,
				label: `${k.kid} [${k.alg}] — status: ${k.status}${k.kid === defaultTargetKid ? " (Mặc định)" : ""}`,
				hint: k.expiresAt
					? `Hết hạn: ${k.expiresAt.slice(0, 19).replace("T", " ")}`
					: "Không giới hạn hạn dùng",
			})),
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: defaultTargetKid,
	});
	if (isCancel(chosen) || chosen === BACK_VALUE) {
		return;
	}
	const targetKid = String(chosen);

	const currentKey = allKeys.find((k) => k.kid === targetKid);
	if (!currentKey) {
		throw new Error(`Không tìm thấy khóa "${targetKid}" trong Store.`);
	}

	const initialNewKid = defaults.newKid ?? currentKey.kid;
	const newKidInput = await text({
		message: `Mã định danh khóa (kid) [Hiện tại: ${currentKey.kid} — Enter để giữ mặc định, gõ 'back' để quay lại]:`,
		initialValue: initialNewKid,
		defaultValue: initialNewKid,
		placeholder: initialNewKid,
	});
	if (isCancel(newKidInput) || String(newKidInput).trim().toLowerCase() === "back") {
		return;
	}

	const newStatus = await select({
		message: `Trạng thái khóa (status) [Hiện tại: ${currentKey.status}]:`,
		options: [
			{
				value: "active",
				label: "● active — Đang dùng để ký JWT mới & xác thực",
			},
			{
				value: "passive",
				label: "◐ passive — Chỉ dùng xác thực JWT cũ trong thời gian ân hạn",
			},
			{
				value: "revoked",
				label: "✕ revoked — Đã thu hồi (ngừng ký & ngừng xác thực)",
			},
			{
				value: BACK_VALUE,
				label: "⬅️  Quay lại (Back)",
			},
		],
		initialValue: (defaults.status ?? currentKey.status) as string,
	});
	if (isCancel(newStatus) || newStatus === BACK_VALUE) {
		return;
	}

	const defaultExpiryChoice = defaults.clearExpiry ? "clear" : defaults.expiresIn ? "set" : "keep";

	const expiryAction = await select({
		message: `Thời hạn hiệu lực (expiresAt) [Hiện tại: ${currentKey.expiresAt ? currentKey.expiresAt.slice(0, 19).replace("T", " ") : "Không giới hạn"}]:`,
		options: [
			{ value: "keep", label: "Giữ nguyên thời hạn hiện tại (Mặc định)" },
			{ value: "set", label: "Đặt / Gia hạn thời hạn mới (ví dụ: 7d, 30d, 24h)" },
			{ value: "clear", label: "Xóa thời hạn (Không bao giờ hết hạn)" },
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: defaultExpiryChoice,
	});
	if (isCancel(expiryAction) || expiryAction === BACK_VALUE) {
		return;
	}

	let expiresIn: string | undefined;
	let clearExpiry = false;
	if (expiryAction === "set") {
		const defaultDur = defaults.expiresIn ?? "7d";
		const dur = await text({
			message: "Nhập khoảng thời gian hiệu lực mới tính từ hiện tại (ví dụ: 7d, 30d, 24h):",
			initialValue: defaultDur,
			defaultValue: defaultDur,
			placeholder: defaultDur,
		});
		if (isCancel(dur)) {
			return;
		}
		expiresIn = String(dur || defaultDur).trim();
	} else if (expiryAction === "clear") {
		clearExpiry = true;
	}

	const { record, diff } = await manager.editKey(currentKey.kid, {
		newKid: String(newKidInput || initialNewKid).trim(),
		status: newStatus as KeyStatus,
		expiresIn,
		clearExpiry,
	});

	note(renderMutationDiff(diff), "Kết quả cập nhật khóa");
	log.success(
		`Đã cập nhật thành công khóa "${pc.cyan(record.kid)}" (status: ${record.status}, pem: ${record.privateKeyPath}).`,
	);
}

/**
 * Luồng import khóa từ file .pem hoặc .json với giá trị mặc định.
 */
export async function interactiveImportFlow(
	manager: KeyManagerService,
	defaults: {
		filePath?: string;
		alg?: SigningAlgorithm;
		kid?: string;
		status?: KeyStatus;
		passphrase?: string;
	} = {},
): Promise<void> {
	const defaultFile = defaults.filePath ?? "./private.pem";
	const enteredFile = await text({
		message: "Đường dẫn file khóa cần import (.pem PKCS#8 hoặc .json JWK, gõ 'back' để quay lại):",
		initialValue: defaultFile,
		defaultValue: defaultFile,
		placeholder: defaultFile,
	});
	if (isCancel(enteredFile) || String(enteredFile).trim().toLowerCase() === "back") {
		return;
	}
	const resolvedPath = resolve(process.cwd(), String(enteredFile || defaultFile).trim());
	const file = Bun.file(resolvedPath);
	if (!(await file.exists())) {
		throw new Error(`Không tìm thấy file cần import tại: ${resolvedPath}`);
	}

	const algChoice = await select({
		message: "Thuật toán của khóa (alg):",
		options: [
			...SUPPORTED_ALGORITHMS.map((a) => ({
				value: a,
				label: a === (defaults.alg ?? "RS256") ? `${a} (Mặc định)` : a,
			})),
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: (defaults.alg ?? "RS256") as string,
	});
	if (isCancel(algChoice) || algChoice === BACK_VALUE) {
		return;
	}

	const defaultKid = defaults.kid ?? "auto";
	const kidInput = await text({
		message:
			"Mã định danh khóa (kid) [Mặc định: 'auto' = tự sinh hoặc lấy từ JWK, 'back' để quay lại]:",
		initialValue: defaultKid,
		defaultValue: defaultKid,
		placeholder: defaultKid,
	});
	if (isCancel(kidInput) || String(kidInput).trim().toLowerCase() === "back") {
		return;
	}
	const resolvedKid =
		!kidInput || String(kidInput).trim().toLowerCase() === "auto"
			? undefined
			: String(kidInput).trim();

	const statusChoice = await select({
		message: "Trạng thái khóa sau khi import (status):",
		options: [
			{ value: "active", label: "● active (Mặc định)" },
			{ value: "passive", label: "◐ passive" },
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: (defaults.status ?? "active") as string,
	});
	if (isCancel(statusChoice) || statusChoice === BACK_VALUE) {
		return;
	}

	await manager.initStore();
	const rawContent = await file.text();
	const { record, diff } = await manager.importKey({
		rawContent,
		alg: algChoice as SigningAlgorithm,
		kid: resolvedKid,
		status: statusChoice as KeyStatus,
		passphrase: defaults.passphrase,
	});

	note(renderMutationDiff(diff), "Kết quả Import");
	log.success(
		`Đã import thành công khóa "${pc.cyan(record.kid)}" (${record.alg}) → Private Key: ${record.privateKeyPath}`,
	);
}

/**
 * Luồng ký thử JWT (sign) với giá trị mặc định.
 */
export async function interactiveSignFlow(
	manager: KeyManagerService,
	defaults: {
		data?: string;
		kid?: string;
		expiresIn?: string;
		iss?: string;
		sub?: string;
		aud?: string;
		passphrase?: string;
	} = {},
): Promise<void> {
	const keys = await manager.listKeys();
	if (keys.length === 0) {
		log.warn("Chưa có khóa nào trong Store để ký JWT.");
		return;
	}
	const defaultKid =
		defaults.kid && keys.some((k) => k.kid === defaults.kid)
			? defaults.kid
			: (keys.find((k) => k.status === "active")?.kid ?? keys[0]!.kid);

	const chosenKid = await select({
		message: "Chọn khóa dùng để ký JWT:",
		options: [
			...keys.map((k) => ({
				value: k.kid,
				label: `${k.kid} [${k.alg}] — status: ${k.status}${k.kid === defaultKid ? " (Mặc định)" : ""}`,
			})),
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: defaultKid,
	});
	if (isCancel(chosenKid) || chosenKid === BACK_VALUE) {
		return;
	}

	const defaultPayload = defaults.data ?? '{"sub":"test-user"}';
	const payloadInput = await text({
		message: "Payload JSON của JWT (gõ 'back' để quay lại):",
		initialValue: defaultPayload,
		defaultValue: defaultPayload,
		placeholder: defaultPayload,
	});
	if (isCancel(payloadInput) || String(payloadInput).trim().toLowerCase() === "back") {
		return;
	}

	const defaultExp = defaults.expiresIn ?? "1h";
	const expInput = await text({
		message: "Thời hạn hiệu lực của JWT (expiresIn, ví dụ: 1h, 15m, 7d):",
		initialValue: defaultExp,
		defaultValue: defaultExp,
		placeholder: defaultExp,
	});
	if (isCancel(expInput) || String(expInput).trim().toLowerCase() === "back") {
		return;
	}

	const payload = JSON.parse(String(payloadInput || defaultPayload)) as Record<string, unknown>;
	const { token, usedKey } = await manager.signJwt({
		payload,
		kid: String(chosenKid),
		expiresIn: String(expInput || defaultExp).trim(),
		issuer: defaults.iss,
		subject: defaults.sub,
		audience: defaults.aud,
		passphrase: defaults.passphrase,
	});

	note(token, `JWT đã ký bởi ${usedKey.kid} (${usedKey.alg})`);
}

/**
 * Luồng xác thực JWT (verify) với giá trị mặc định.
 */
export async function interactiveVerifyFlow(
	manager: KeyManagerService,
	defaults: {
		token?: string;
		kid?: string;
		allowExpiredKey?: boolean;
	} = {},
): Promise<void> {
	const tokenInput = await text({
		message: "Nhập chuỗi JWT cần xác thực (gõ 'back' để quay lại):",
		initialValue: defaults.token ?? "",
		placeholder: "eyJhbGciOi...",
		validate: (val) => (!val || !val.trim() ? "Vui lòng nhập chuỗi JWT" : undefined),
	});
	if (isCancel(tokenInput) || String(tokenInput).trim().toLowerCase() === "back") {
		return;
	}

	const keys = await manager.listKeys();
	const chosenKid = await select({
		message: "Chọn khóa xác thực (kid):",
		options: [
			{ value: "__auto__", label: "🔍 Tự động nhận diện theo JWT Header (Mặc định)" },
			...keys.map((k) => ({
				value: k.kid,
				label: `${k.kid} [${k.alg}] — status: ${k.status}`,
			})),
			{ value: BACK_VALUE, label: "⬅️  Quay lại (Back)" },
		],
		initialValue: defaults.kid ?? "__auto__",
	});
	if (isCancel(chosenKid) || chosenKid === BACK_VALUE) {
		return;
	}

	const allowExpired = await confirm({
		message: "Cho phép xác thực cả bằng khóa đã thu hồi (revoked) hoặc hết hạn ân hạn?",
		initialValue: Boolean(defaults.allowExpiredKey),
	});
	if (isCancel(allowExpired)) {
		return;
	}

	const result = await manager.verifyJwt(String(tokenInput).trim(), {
		kid: chosenKid === "__auto__" ? undefined : String(chosenKid),
		allowRevokedOrExpiredKey: allowExpired,
	});

	log.success(
		`JWT Hợp lệ! Xác thực bởi khóa: ${pc.bold(pc.cyan(result.matchedKey.kid))} (${result.matchedKey.alg}, status=${result.matchedKey.status})`,
	);
	console.log(pc.bold("Header:"), JSON.stringify(result.protectedHeader));
	console.log(pc.bold("Payload:"), JSON.stringify(result.payload, null, 2));
}

/**
 * Hiển thị bảng danh sách khóa kèm menu thao tác nhanh: Sửa (Edit), Xóa (Remove), Xem chi tiết (Inspect), Quay lại (Back).
 */
export async function interactiveListFlow(
	manager: KeyManagerService,
	filterStatus?: KeyStatus,
): Promise<void> {
	while (true) {
		const keys = await manager.listKeys({ status: filterStatus });
		const pemMap = new Map<string, boolean>();
		for (const k of keys) {
			pemMap.set(k.kid, await manager.vault.exists(k.privateKeyPath));
		}
		console.log("\n" + renderKeyTable(keys, pemMap) + "\n");

		if (keys.length === 0) {
			return;
		}

		const action = await select({
			message: "Thao tác trên danh sách khóa (Chọn Sửa, Xóa, Xem chi tiết hoặc Quay lại):",
			options: [
				{ value: "edit", label: "✏️  Sửa khóa (Đổi kid, trạng thái status, hạn dùng expiresAt)" },
				{
					value: "remove",
					label: "🗑️  Xóa khóa (Chọn 1 hoặc nhiều khóa đưa vào Thùng rác / Xóa vĩnh viễn)",
				},
				{ value: "inspect", label: "🔍 Xem chi tiết khóa & Public Key SPKI PEM" },
				{ value: BACK_VALUE, label: "⬅️  Quay lại / Thoát (Back)" },
			],
			initialValue: "edit",
		});

		if (isCancel(action) || action === BACK_VALUE) {
			return;
		}

		if (action === "edit") {
			await interactiveEditFlow(manager);
			continue;
		}

		if (action === "remove") {
			await interactiveRemoveFlow(manager);
			continue;
		}

		if (action === "inspect") {
			await interactiveInspectFlow(manager);
		}
	}
}

export async function runInteractiveWizard(
	manager: KeyManagerService,
	defaultPassphrase?: string,
): Promise<void> {
	intro(pc.bgCyan(pc.black(" jwksctl — Trình Quản Lý JWKS Tương Tác ")));

	await manager.initStore();

	while (true) {
		const action = await select({
			message: `Store hiện tại: ${pc.cyan(manager.adapter.location)} (${manager.adapter.kind}). Bạn muốn thực hiện thao tác nào?`,
			options: [
				{ value: "list", label: "📋 Liệt kê danh sách khóa — kèm Sửa / Xóa (list)" },
				{ value: "generate", label: "✨ Tạo cặp khóa mới (generate)" },
				{ value: "edit", label: "✏️  Sửa thông tin khóa (edit)" },
				{ value: "rotate", label: "🔄 Xoay vòng khóa an toàn (rotate)" },
				{ value: "inspect", label: "🔍 Xem chi tiết khóa & SPKI PEM (inspect)" },
				{ value: "remove", label: "🗑️  Xóa 1 hoặc nhiều khóa vào Thùng rác (remove)" },
				{ value: "restore", label: "♻️  Khôi phục khóa & file .pem từ Thùng rác (restore)" },
				{ value: "trash", label: "🧹 Xem / Dọn sạch Thùng rác (trash)" },
				{ value: "export", label: "📤 Xuất Public JWKS chuẩn RFC 7517 (export)" },
				{ value: "check", label: "🛡️  Kiểm tra toàn vẹn Store & file .pem (check)" },
				{ value: "exit", label: "🚪 Thoát chương trình (exit)" },
			],
		});

		if (isCancel(action) || action === "exit") {
			outro(pc.dim("Đã thoát trình quản lý JWKS."));
			return;
		}

		switch (action) {
			case "list": {
				await interactiveListFlow(manager);
				break;
			}

			case "edit": {
				await interactiveEditFlow(manager);
				break;
			}

			case "generate": {
				await interactiveGenerateFlow(manager, { passphrase: defaultPassphrase });
				break;
			}

			case "rotate": {
				await interactiveRotateFlow(manager, { passphrase: defaultPassphrase });
				break;
			}

			case "inspect": {
				await interactiveInspectFlow(manager);
				break;
			}

			case "remove": {
				await interactiveRemoveFlow(manager);
				break;
			}

			case "restore": {
				await interactiveRestoreFlow(manager);
				break;
			}

			case "trash": {
				await interactiveTrashFlow(manager);
				break;
			}

			case "export": {
				await interactiveExportFlow(manager);
				break;
			}

			case "check": {
				const report = await manager.checkIntegrity();
				note(renderIntegrityReport(report, manager.adapter.location), "Báo cáo Toàn vẹn JWKS");
				break;
			}
		}
	}
}
