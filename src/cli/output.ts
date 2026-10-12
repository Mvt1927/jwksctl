import pc from "picocolors";
import {
	isRecordExpired,
	type InspectKeyResult,
	type IntegrityCheckReport,
} from "../core/key-manager.ts";
import type { JwkRecord, KeyStatus, MutationDiff, TrashItem } from "../core/types.ts";

export function formatStatusBadge(status: KeyStatus, expired: boolean = false): string {
	if (status === "active") {
		return pc.green(pc.bold("● active"));
	}
	if (status === "passive") {
		return expired ? pc.red("◌ passive (expired)") : pc.yellow("◐ passive (grace)");
	}
	return pc.red("✕ revoked");
}

function padRight(str: string, width: number): string {
	// Bỏ mã màu ANSI khi tính độ dài hiển thị
	// eslint-disable-next-line no-control-regex
	const visible = str.replace(/\x1b\[[0-9;]*m/g, "");
	const pad = Math.max(0, width - visible.length);
	return str + " ".repeat(pad);
}

export function renderKeyTable(
	records: readonly JwkRecord[],
	pemExistsMap?: ReadonlyMap<string, boolean>,
): string {
	if (records.length === 0) {
		return pc.dim("  (Kho lưu trữ hiện chưa có khóa nào)");
	}

	const headers = [
		{ label: "KID", width: 24 },
		{ label: "ALG", width: 8 },
		{ label: "KTY", width: 6 },
		{ label: "STATUS", width: 20 },
		{ label: "ENC", width: 6 },
		{ label: "PEM FILE", width: 32 },
		{ label: "EXPIRES AT", width: 22 },
	];

	const headerLine = headers.map((h) => padRight(pc.bold(pc.cyan(h.label)), h.width)).join("  ");
	const separator = headers.map((h) => pc.dim("─".repeat(h.width))).join("──");

	const rows = records.map((rec) => {
		const expired = isRecordExpired(rec);
		const pemOk = pemExistsMap ? pemExistsMap.get(rec.kid) : undefined;
		const pemDisplay =
			pemOk === false ? pc.red(`✗ ${rec.privateKeyPath}`) : pc.dim(rec.privateKeyPath);

		const encDisplay = rec.isPrivateKeyEncrypted ? pc.green("AES") : pc.dim("no");
		const expiresDisplay = rec.expiresAt
			? expired
				? pc.red(rec.expiresAt.slice(0, 19).replace("T", " "))
				: pc.yellow(rec.expiresAt.slice(0, 19).replace("T", " "))
			: pc.dim("-");

		return [
			padRight(pc.bold(rec.kid), headers[0]!.width),
			padRight(rec.alg, headers[1]!.width),
			padRight(rec.kty, headers[2]!.width),
			padRight(formatStatusBadge(rec.status, expired), headers[3]!.width),
			padRight(encDisplay, headers[4]!.width),
			padRight(pemDisplay, headers[5]!.width),
			padRight(expiresDisplay, headers[6]!.width),
		].join("  ");
	});

	return [headerLine, separator, ...rows].join("\n");
}

export function renderMutationDiff(diff: MutationDiff): string {
	const lines: string[] = [];
	lines.push(
		pc.bold(
			`Bảng đối chiếu thay đổi (Trước: ${diff.beforeCount} khóa → Sau: ${diff.afterCount} khóa | Giữ nguyên 100%: ${diff.unchangedCount} khóa):`,
		),
	);

	for (const added of diff.added) {
		lines.push(
			`  ${pc.green("+ [THÊM MỚI]")} ${pc.bold(added.kid)} (${added.alg}, status=${added.status}, pem=${added.privateKeyPath})`,
		);
	}

	for (const upd of diff.updated) {
		lines.push(
			`  ${pc.yellow("~ [CẬP NHẬT]")} ${pc.bold(upd.after.kid)} (status: ${upd.before.status} → ${upd.after.status})`,
		);
	}

	for (const rem of diff.removed) {
		const activeWarn = rem.status === "active" ? pc.bgRed(pc.white(" [ĐANG ACTIVE!] ")) : "";
		lines.push(
			`  ${pc.red("- [XÓA KHÓA]")} ${pc.bold(rem.kid)} (${rem.alg}, status=${rem.status})${activeWarn}`,
		);
	}

	if (diff.added.length === 0 && diff.updated.length === 0 && diff.removed.length === 0) {
		lines.push(pc.dim("  (Không có sự thay đổi nào)"));
	}

	return lines.join("\n");
}

export function renderInspectReport(info: InspectKeyResult): string {
	const { record, privateKeyFileExists, isExpired, publicPem } = info;
	const lines: string[] = [
		`${pc.bold("KID:")}              ${pc.cyan(record.kid)}`,
		`${pc.bold("Thuật toán (alg):")} ${record.alg} (${record.kty})`,
		`${pc.bold("Trạng thái:")}       ${formatStatusBadge(record.status, isExpired)}`,
		`${pc.bold("File Private Key:")} ${record.privateKeyPath} ${
			privateKeyFileExists ? pc.green("(✓ Tồn tại trên đĩa)") : pc.red("(✗ KHÔNG TÌM THẤY FILE!)")
		}`,
		`${pc.bold("Mã hóa AES-GCM:")}   ${record.isPrivateKeyEncrypted ? pc.green("Có") : "Không"}`,
		`${pc.bold("Ngày tạo:")}         ${record.createdAt}`,
		`${pc.bold("Ngày xoay vòng:")}   ${record.rotatedAt ?? "-"}`,
		`${pc.bold("Ngày hết hạn:")}     ${record.expiresAt ?? "-"}`,
		"",
		pc.bold("Public Key (SPKI PEM):"),
		pc.dim(publicPem.trim()),
	];
	return lines.join("\n");
}

export function renderIntegrityReport(report: IntegrityCheckReport, storeLocation: string): string {
	const lines: string[] = [
		`${pc.bold("Nguồn lưu trữ:")}    ${storeLocation}`,
		`${pc.bold("Tổng số khóa:")}     ${report.totalKeys} (Active: ${pc.green(String(report.activeKeys))}, Passive: ${pc.yellow(String(report.passiveKeys))}, Revoked: ${pc.red(String(report.revokedKeys))})`,
	];

	if (report.expiredPassiveKeys.length > 0) {
		lines.push(
			`${pc.yellow("⚠ Khóa passive đã hết hạn ân hạn:")} ${report.expiredPassiveKeys.join(", ")} (Gợi ý chạy: ${pc.cyan("jwksctl prune")})`,
		);
	}

	if (report.missingPrivateKeyFiles.length > 0) {
		lines.push(pc.red("✗ Phát hiện thiếu file Private Key (.pem) trên đĩa:"));
		for (const missing of report.missingPrivateKeyFiles) {
			lines.push(`  - KID ${pc.bold(missing.kid)}: không tìm thấy ${missing.path}`);
		}
	} else {
		lines.push(pc.green("✓ Toàn bộ đường dẫn privateKeyPath (.pem) đều tồn tại và hợp lệ."));
	}

	if (report.activeKeys === 0) {
		lines.push(pc.yellow("⚠ Chưa có khóa nào ở trạng thái 'active' để ký JWT mới."));
	}

	lines.push(
		report.valid
			? pc.green(pc.bold("⇒ Kết luận: Kho lưu trữ JWKS hoàn toàn khỏe mạnh và toàn vẹn."))
			: pc.red(pc.bold("⇒ Kết luận: Kho lưu trữ có cảnh báo cần xử lý.")),
	);

	return lines.join("\n");
}

export function renderTrashTable(items: readonly TrashItem[]): string {
	if (items.length === 0) {
		return pc.dim("  (Thùng rác .trash hiện đang trống)");
	}

	const headers = [
		{ label: "KID", width: 24 },
		{ label: "ALG", width: 8 },
		{ label: "STATUS CŨ", width: 14 },
		{ label: "DELETED AT", width: 20 },
		{ label: "TRASH PEM", width: 34 },
		{ label: "ORIGINAL PEM PATH", width: 28 },
	];

	const headerLine = headers.map((h) => padRight(pc.bold(pc.cyan(h.label)), h.width)).join("  ");
	const separator = headers.map((h) => pc.dim("─".repeat(h.width))).join("──");

	const rows = items.map((item) => {
		const { record } = item;
		const deletedAtStr = item.deletedAt.slice(0, 19).replace("T", " ");
		const trashPemDisplay = item.trashPemPath
			? pc.green(`✓ ${item.trashPemPath}`)
			: pc.red("✗ Không có file .pem");

		return [
			padRight(pc.bold(record.kid), headers[0]!.width),
			padRight(record.alg, headers[1]!.width),
			padRight(record.status, headers[2]!.width),
			padRight(pc.yellow(deletedAtStr), headers[3]!.width),
			padRight(trashPemDisplay, headers[4]!.width),
			padRight(pc.dim(record.privateKeyPath), headers[5]!.width),
		].join("  ");
	});

	return [headerLine, separator, ...rows].join("\n");
}
