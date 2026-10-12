import {
	cancel,
	confirm,
	intro,
	isCancel,
	log,
	multiselect,
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
import { SUPPORTED_ALGORITHMS, type SigningAlgorithm } from "../core/types.ts";
import {
	renderExportMergeTable,
	renderInspectReport,
	renderIntegrityReport,
	renderKeyTable,
	renderMutationDiff,
	renderTrashTable,
} from "./output.ts";

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

	let selectedKids = preselectedKids ?? [];
	if (selectedKids.length === 0) {
		const picked = await multiselect({
			message: "Chọn 1 hoặc nhiều khóa cần xóa (Dùng phím Space để tích chọn, Enter để xác nhận):",
			options: allKeys.map((k) => ({
				value: k.kid,
				label: `${k.kid} [${k.alg}] — status: ${k.status}`,
				hint: k.status === "active" ? "ĐANG ACTIVE (Cẩn trọng!)" : `pem: ${k.privateKeyPath}`,
			})),
			required: true,
		});

		if (isCancel(picked)) {
			cancel("Đã hủy thao tác xóa khóa.");
			return;
		}
		selectedKids = picked as string[];
	}

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
			cancel("Đã hủy thao tác để bảo vệ khóa đang active.");
			return;
		}
		allowForce = true;
	}

	const diffPreview = await manager.previewRemoveKeys(selectedKids, {
		force: allowForce,
	});
	note(renderMutationDiff(diffPreview), "Xem trước thay đổi (SafeMutationGuard)");

	let isPermanent = Boolean(permanentOption);
	if (!permanentOption) {
		const mode = await select({
			message: `Chọn chế độ xóa cho ${selectedKids.length} khóa đã chọn (còn lại ${diffPreview.afterCount} khóa giữ nguyên 100%):`,
			options: [
				{
					value: "trash",
					label: `♻️  Đưa khóa & file .pem vào Thùng rác (${manager.vault.trashDir}) — Khuyên dùng`,
					hint: "Có thể khôi phục lại cả khóa lẫn file .pem bằng lệnh restore",
				},
				{
					value: "permanent",
					label: "🔥 Xóa vĩnh viễn (Xóa hẳn khỏi Store và xóa vĩnh viễn file .pem trên đĩa)",
					hint: "Không thể khôi phục lại file .pem",
				},
			],
			initialValue: "trash",
		});
		if (isCancel(mode)) {
			cancel("Đã hủy thao tác xóa khóa.");
			return;
		}
		isPermanent = mode === "permanent";
	}

	const confirmDelete = await confirm({
		message: isPermanent
			? `Xác nhận XÓA VĨNH VIỄN ${selectedKids.length} khóa và file .pem tương ứng?`
			: `Xác nhận chuyển ${selectedKids.length} khóa và file .pem vào Thùng rác?`,
		initialValue: !isPermanent,
	});
	if (isCancel(confirmDelete) || !confirmDelete) {
		cancel("Đã hủy thao tác xóa khóa.");
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
export async function interactiveRestoreFlow(manager: KeyManagerService): Promise<void> {
	const trashItems = await manager.listTrash();
	if (trashItems.length === 0) {
		log.warn(`Thùng rác (${manager.vault.trashDir}) hiện đang trống.`);
		if (manager.adapter.restoreBackup) {
			const askBak = await confirm({
				message: "Bạn có muốn thử khôi phục từ file sao lưu .bak gần nhất không?",
				initialValue: false,
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

	const picked = await multiselect({
		message:
			"Chọn 1 hoặc nhiều khóa trong Thùng rác cần khôi phục (Space để chọn, Enter để xác nhận):",
		options: trashItems.map((item) => ({
			value: item.record.kid,
			label: `${item.record.kid} [${item.record.alg}] — status cũ: ${item.record.status}`,
			hint: `Xóa lúc: ${item.deletedAt.slice(0, 19).replace("T", " ")} | pem: ${
				item.trashPemPath
					? `✓ Có file trong .trash → trả về ${item.record.privateKeyPath}`
					: "✗ Không có file .pem"
			}`,
		})),
		required: true,
	});

	if (isCancel(picked)) {
		cancel("Đã hủy thao tác khôi phục.");
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
	const trashItems = await manager.listTrash();
	console.log("\n" + renderTrashTable(trashItems) + "\n");

	if (trashItems.length === 0) {
		return;
	}

	const subAction = await select({
		message: `Thùng rác hiện có ${trashItems.length} khóa. Bạn muốn làm gì?`,
		options: [
			{ value: "restore", label: "♻️  Chọn khóa để khôi phục lại vào Store & trả lại file .pem" },
			{ value: "empty", label: "🔥 Dọn sạch Thùng rác (Xóa vĩnh viễn các file .pem trong .trash)" },
			{ value: "back", label: "⬅️  Quay lại / Thoát" },
		],
	});

	if (isCancel(subAction) || subAction === "back") {
		return;
	}

	if (subAction === "restore") {
		await interactiveRestoreFlow(manager);
		return;
	}

	if (subAction === "empty") {
		const confirmEmpty = await confirm({
			message: `Bạn có chắc chắn muốn XÓA VĨNH VIỄN toàn bộ ${trashItems.length} khóa và file .pem trong Thùng rác không?`,
			initialValue: false,
		});
		if (isCancel(confirmEmpty) || !confirmEmpty) {
			cancel("Đã hủy thao tác dọn Thùng rác.");
			return;
		}
		const count = await manager.emptyTrash();
		log.success(`Đã dọn sạch vĩnh viễn ${count} mục khỏi Thùng rác.`);
	}
}

/**
 * Luồng xuất Public JWKS ra file đích:
 * - Tự động kiểm tra xem file đích (ví dụ ./jwks.json) đã tồn tại chưa.
 * - Nếu đã tồn tại, hiển thị Bảng đối chiếu Merge và cho phép tích chọn (Checkbox) khóa nào GIỮ, khóa nào BỎ.
 */
export async function interactiveExportFlow(
	manager: KeyManagerService,
	options: { outputFile?: string; includePassive?: boolean } = {},
): Promise<void> {
	let targetFile = options.outputFile;
	const cwdJwksPath = resolve(process.cwd(), "jwks.json");
	const storeAbsPath = resolve(manager.adapter.location);
	const defaultTarget = cwdJwksPath === storeAbsPath ? "./public-jwks.json" : "./jwks.json";

	if (!targetFile) {
		const entered = await text({
			message:
				"Nhập đường dẫn file đích muốn xuất Public JWKS (hoặc gõ 'stdout' để chỉ in ra màn hình):",
			initialValue: defaultTarget,
			placeholder: defaultTarget,
		});
		if (isCancel(entered)) {
			cancel("Đã hủy thao tác export.");
			return;
		}
		targetFile = String(entered || defaultTarget).trim();
	}

	if (targetFile.toLowerCase() === "stdout" || targetFile === "-") {
		const exported = await manager.exportPublicJwks({
			includePassive: options.includePassive,
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
		includePassive: options.includePassive,
	});

	if (!plan.targetFileExists) {
		const allKids = plan.candidates.map((c) => c.kid);
		const res = await manager.writeExportedJwksFile(absOutPath, allKids, plan);
		log.success(
			`Đã tạo mới và xuất ${res.keptCount} Public JWK chuẩn RFC 7517 ra file: ${pc.bold(absOutPath)}`,
		);
		return;
	}

	// File đích đã tồn tại -> Hiển thị Bảng đối chiếu Merge & Checkbox chọn khóa Giữ / Bỏ
	note(
		renderExportMergeTable(plan, absOutPath),
		"Phát hiện file đã tồn tại — Bảng đối chiếu Merge JWKS",
	);

	if (plan.candidates.length === 0) {
		log.warn("Không có khóa nào trong cả file đích lẫn Store để xuất.");
		return;
	}

	const pickedKids = await multiselect({
		message:
			"Chọn các khóa muốn GIỮ LẠI trong file xuất ra (Dùng phím Space để Giữ/Bỏ, Enter để lưu):",
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
	});

	if (isCancel(pickedKids)) {
		cancel("Đã hủy thao tác Merge & Export.");
		return;
	}

	const selectedKids = pickedKids as string[];
	const res = await manager.writeExportedJwksFile(absOutPath, selectedKids, plan);

	log.success(
		`Đã Merge & xuất thành công ra file: ${pc.bold(absOutPath)} (Giữ lại: ${pc.green(String(res.keptCount))} khóa | Loại bỏ: ${pc.yellow(String(res.droppedCount))} khóa${
			res.droppedKids.length > 0 ? ` [${res.droppedKids.join(", ")}]` : ""
		})`,
	);
}

export async function runInteractiveWizard(
	manager: KeyManagerService,
	defaultPassphrase?: string,
): Promise<void> {
	intro(pc.bgCyan(pc.black(" jwksctl — Trình Quản Lý JWKS Tương Tác ")));

	await manager.initStore();

	const action = await select({
		message: `Store hiện tại: ${pc.cyan(manager.adapter.location)} (${manager.adapter.kind}). Bạn muốn thực hiện thao tác nào?`,
		options: [
			{ value: "list", label: "📋 Liệt kê danh sách khóa (list)" },
			{ value: "generate", label: "✨ Tạo cặp khóa mới (generate)" },
			{ value: "rotate", label: "🔄 Xoay vòng khóa an toàn (rotate)" },
			{ value: "inspect", label: "🔍 Xem chi tiết khóa & SPKI PEM (inspect)" },
			{ value: "remove", label: "🗑️  Xóa 1 hoặc nhiều khóa vào Thùng rác (remove)" },
			{ value: "restore", label: "♻️  Khôi phục khóa & file .pem từ Thùng rác (restore)" },
			{ value: "trash", label: "🧹 Xem / Dọn sạch Thùng rác (trash)" },
			{ value: "export", label: "📤 Xuất Public JWKS chuẩn RFC 7517 (export)" },
			{ value: "check", label: "🛡️  Kiểm tra toàn vẹn Store & file .pem (check)" },
		],
	});

	if (isCancel(action)) {
		cancel("Đã thoát trình tương tác.");
		return;
	}

	switch (action) {
		case "list": {
			const keys = await manager.listKeys();
			const pemMap = new Map<string, boolean>();
			for (const k of keys) {
				pemMap.set(k.kid, await manager.vault.exists(k.privateKeyPath));
			}
			console.log("\n" + renderKeyTable(keys, pemMap) + "\n");
			break;
		}

		case "generate": {
			const alg = await select({
				message: "Chọn thuật toán ký (alg):",
				options: SUPPORTED_ALGORITHMS.map((a) => ({
					value: a,
					label: a,
					hint:
						a === "EdDSA"
							? "Ed25519 (Nhanh, khóa nhỏ, hiện đại)"
							: a === "ES256"
								? "ECDSA P-256 (Phổ biến, gọn nhẹ)"
								: a === "RS256"
									? "RSA 2048-bit (Tương thích rộng nhất)"
									: undefined,
				})),
				initialValue: "RS256" as SigningAlgorithm,
			});
			if (isCancel(alg)) {
				cancel("Đã hủy.");
				return;
			}

			const customKid = await text({
				message: "Nhập mã định danh khóa (kid) [Để trống để tự sinh theo chuẩn RFC 7638]:",
				placeholder: "Tự động (YYYY-MM-<thumbprint>)",
			});
			if (isCancel(customKid)) {
				cancel("Đã hủy.");
				return;
			}

			const wantEncrypt = await confirm({
				message: "Bạn có muốn mã hóa file Private Key (.pem) bằng AES-256-GCM không?",
				initialValue: Boolean(defaultPassphrase),
			});
			if (isCancel(wantEncrypt)) {
				cancel("Đã hủy.");
				return;
			}

			let passphrase = defaultPassphrase;
			if (wantEncrypt && !passphrase) {
				const entered = await password({
					message: "Nhập passphrase để mã hóa file Private Key (.pem):",
					validate: (val) =>
						!val || val.length < 4 ? "Passphrase cần ít nhất 4 ký tự" : undefined,
				});
				if (isCancel(entered)) {
					cancel("Đã hủy.");
					return;
				}
				passphrase = entered;
			}

			const s = spinner();
			s.start(`Đang sinh cặp khóa ${alg}...`);
			const { record, diff } = await manager.generateKey({
				alg: alg as SigningAlgorithm,
				kid: customKid ? String(customKid).trim() : undefined,
				passphrase: wantEncrypt ? passphrase : undefined,
			});
			s.stop(`Đã tạo thành công khóa "${pc.cyan(record.kid)}"!`);
			note(renderMutationDiff(diff), "Kết quả cập nhật Store");
			break;
		}

		case "rotate": {
			const grace = await text({
				message: "Thời gian ân hạn (Grace Period) cho khóa cũ ở trạng thái 'passive':",
				initialValue: "7d",
				placeholder: "7d (hoặc 24h, 30m)",
			});
			if (isCancel(grace)) {
				cancel("Đã hủy.");
				return;
			}

			const s = spinner();
			s.start("Đang xoay vòng khóa...");
			const { newRecord, demotedKids, diff } = await manager.rotateKeys({
				gracePeriod: String(grace || "7d"),
				passphrase: defaultPassphrase,
			});
			s.stop(
				`Đã xoay vòng khóa thành công! Khóa active mới: ${pc.green(newRecord.kid)} (Chuyển sang passive: ${demotedKids.join(", ") || "không có"})`,
			);
			note(renderMutationDiff(diff), "Kết quả Rotate");
			break;
		}

		case "inspect": {
			const keys = await manager.listKeys();
			if (keys.length === 0) {
				log.warn("Chưa có khóa nào trong Store.");
				break;
			}
			const chosenKid = await select({
				message: "Chọn khóa cần xem chi tiết:",
				options: keys.map((k) => ({
					value: k.kid,
					label: `${k.kid} (${k.alg} - ${k.status})`,
				})),
			});
			if (isCancel(chosenKid)) {
				cancel("Đã hủy.");
				return;
			}
			const info = await manager.inspectKey(String(chosenKid));
			note(renderInspectReport(info), `Chi tiết khóa ${info.record.kid}`);
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

	outro(pc.dim("Hoàn tất thao tác."));
}
