import { copyFile, mkdir, rename, rm, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type { JwkRecord, TrashItem } from "./types.ts";

const ENCRYPTED_HEADER = "-----BEGIN ENCRYPTED JWKSCTL PRIVATE KEY-----";
const ENCRYPTED_FOOTER = "-----END ENCRYPTED JWKSCTL PRIVATE KEY-----";
const PBKDF2_ITERATIONS = 100_000;

interface EncryptedPayload {
	v: 1;
	alg: "AES-256-GCM";
	kdf: "PBKDF2-SHA256";
	iter: number;
	salt: string;
	iv: string;
	ciphertext: string;
}

interface TrashManifest {
	items: TrashItem[];
}

async function deriveAesKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
	const enc = new TextEncoder();
	const baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, [
		"deriveKey",
	]);
	return crypto.subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: new Uint8Array(salt),
			iterations: PBKDF2_ITERATIONS,
			hash: "SHA-256",
		},
		baseKey,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

export async function encryptPemContent(pkcs8Pem: string, passphrase: string): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const key = await deriveAesKey(passphrase, salt);
	const encoded = new TextEncoder().encode(pkcs8Pem);
	const cipherBuffer = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: new Uint8Array(iv) },
		key,
		encoded,
	);

	const payload: EncryptedPayload = {
		v: 1,
		alg: "AES-256-GCM",
		kdf: "PBKDF2-SHA256",
		iter: PBKDF2_ITERATIONS,
		salt: Buffer.from(salt).toString("base64"),
		iv: Buffer.from(iv).toString("base64"),
		ciphertext: Buffer.from(cipherBuffer).toString("base64"),
	};

	const base64Body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
	const lines = base64Body.match(/.{1,64}/g) ?? [base64Body];
	return `${ENCRYPTED_HEADER}\n${lines.join("\n")}\n${ENCRYPTED_FOOTER}\n`;
}

export async function decryptPemContent(content: string, passphrase?: string): Promise<string> {
	const trimmed = content.trim();
	if (!trimmed.startsWith(ENCRYPTED_HEADER)) {
		return content;
	}
	if (!passphrase) {
		throw new Error(
			"File Private Key đang được mã hóa AES-256-GCM. Vui lòng cung cấp passphrase (--passphrase hoặc JWKS_PASSPHRASE).",
		);
	}

	const base64Body = trimmed
		.replace(ENCRYPTED_HEADER, "")
		.replace(ENCRYPTED_FOOTER, "")
		.replace(/\s+/g, "");

	let payload: EncryptedPayload;
	try {
		payload = JSON.parse(Buffer.from(base64Body, "base64").toString("utf8")) as EncryptedPayload;
	} catch {
		throw new Error("Định dạng file Private Key mã hóa không hợp lệ hoặc bị hỏng.");
	}

	const salt = new Uint8Array(Buffer.from(payload.salt, "base64"));
	const iv = new Uint8Array(Buffer.from(payload.iv, "base64"));
	const ciphertext = new Uint8Array(Buffer.from(payload.ciphertext, "base64"));
	const key = await deriveAesKey(passphrase, salt);

	try {
		const plainBuffer = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: new Uint8Array(iv) },
			key,
			new Uint8Array(ciphertext),
		);
		return new TextDecoder().decode(plainBuffer);
	} catch {
		throw new Error("Giải mã Private Key thất bại: Sai passphrase hoặc dữ liệu bị thay đổi.");
	}
}

export class PemVault {
	readonly trashDir: string;
	readonly trashManifestPath: string;

	constructor(private readonly baseKeysDir: string = "./keys") {
		this.trashDir = join(this.baseKeysDir, ".trash");
		this.trashManifestPath = resolve(join(this.trashDir, "manifest.json"));
	}

	getKeyFilePath(kid: string): string {
		const safeKid = kid.replace(/[^a-zA-Z0-9._-]/g, "_");
		return join(this.baseKeysDir, `${safeKid}.pem`);
	}

	getTrashPemPath(kid: string): string {
		const safeKid = kid.replace(/[^a-zA-Z0-9._-]/g, "_");
		return join(this.trashDir, `${safeKid}.pem`);
	}

	async savePrivateKey(
		kid: string,
		pkcs8Pem: string,
		passphrase?: string,
	): Promise<{ privateKeyPath: string; isEncrypted: boolean }> {
		const filePath = this.getKeyFilePath(kid);
		const absPath = resolve(filePath);
		await mkdir(dirname(absPath), { recursive: true });

		const isEncrypted = Boolean(passphrase && passphrase.length > 0);
		const contentToWrite = isEncrypted
			? await encryptPemContent(pkcs8Pem, passphrase!)
			: pkcs8Pem.endsWith("\n")
				? pkcs8Pem
				: `${pkcs8Pem}\n`;

		const tmpPath = `${absPath}.tmp.${process.pid}.${Date.now()}`;
		await Bun.write(tmpPath, contentToWrite);
		await rename(tmpPath, absPath);

		return {
			privateKeyPath: filePath.replace(/\\/g, "/"),
			isEncrypted,
		};
	}

	async loadPrivateKey(privateKeyPath: string, passphrase?: string): Promise<string> {
		const absPath = resolve(privateKeyPath);
		const file = Bun.file(absPath);
		if (!(await file.exists())) {
			throw new Error(`Không tìm thấy file Private Key tại đường dẫn: ${privateKeyPath}`);
		}
		const raw = await file.text();
		return decryptPemContent(raw, passphrase);
	}

	async exists(privateKeyPath: string): Promise<boolean> {
		try {
			const info = await stat(resolve(privateKeyPath));
			return info.isFile();
		} catch {
			return false;
		}
	}

	async deletePrivateKey(privateKeyPath: string): Promise<boolean> {
		const absPath = resolve(privateKeyPath);
		if (!(await this.exists(absPath))) {
			return false;
		}
		await rm(absPath, { force: true });
		return true;
	}

	private async readTrashManifest(): Promise<TrashItem[]> {
		const file = Bun.file(this.trashManifestPath);
		if (!(await file.exists())) {
			return [];
		}
		try {
			const parsed = JSON.parse(await file.text()) as TrashManifest;
			return Array.isArray(parsed.items) ? parsed.items : [];
		} catch {
			return [];
		}
	}

	private async writeTrashManifest(items: TrashItem[]): Promise<void> {
		await mkdir(resolve(this.trashDir), { recursive: true });
		const tmpPath = `${this.trashManifestPath}.tmp.${process.pid}.${Date.now()}`;
		await Bun.write(tmpPath, `${JSON.stringify({ items }, null, 2)}\n`);
		await rename(tmpPath, this.trashManifestPath);
	}

	/**
	 * Đưa khóa và file Private Key (.pem) vào Thùng rác (.trash) thay vì xóa vĩnh viễn.
	 */
	async moveToTrash(record: JwkRecord): Promise<TrashItem> {
		await mkdir(resolve(this.trashDir), { recursive: true });
		const srcAbs = resolve(record.privateKeyPath);
		let trashPemPath: string | null = null;

		if (await this.exists(srcAbs)) {
			const relTrashPem = this.getTrashPemPath(record.kid).replace(/\\/g, "/");
			const destAbs = resolve(relTrashPem);
			await copyFile(srcAbs, destAbs);
			await rm(srcAbs, { force: true });
			trashPemPath = relTrashPem;
		}

		const item: TrashItem = {
			record,
			deletedAt: new Date().toISOString(),
			trashPemPath,
		};

		const current = await this.readTrashManifest();
		const filtered = current.filter((x) => x.record.kid !== record.kid);
		filtered.push(item);
		await this.writeTrashManifest(filtered);

		return item;
	}

	async listTrash(): Promise<TrashItem[]> {
		return this.readTrashManifest();
	}

	/**
	 * Khôi phục file .pem và bản ghi JwkRecord từ Thùng rác về lại vị trí gốc.
	 */
	async restoreFromTrash(kid: string): Promise<TrashItem> {
		const current = await this.readTrashManifest();
		const found = current.find((x) => x.record.kid === kid);
		if (!found) {
			throw new Error(`Không tìm thấy khóa "${kid}" trong Thùng rác (${this.trashDir}).`);
		}

		if (found.trashPemPath && (await this.exists(found.trashPemPath))) {
			const destAbs = resolve(found.record.privateKeyPath);
			await mkdir(dirname(destAbs), { recursive: true });
			await copyFile(resolve(found.trashPemPath), destAbs);
			await rm(resolve(found.trashPemPath), { force: true });
		}

		const remaining = current.filter((x) => x.record.kid !== kid);
		await this.writeTrashManifest(remaining);
		return found;
	}

	/**
	 * Tự động khôi phục các file .pem đang nằm trong Thùng rác cho danh sách bản ghi (dùng khi restore từ .bak).
	 */
	async restoreMissingPemsForRecords(records: readonly JwkRecord[]): Promise<string[]> {
		const current = await this.readTrashManifest();
		const trashMap = new Map(current.map((item) => [item.record.kid, item]));
		const restoredPems: string[] = [];
		const restoredKids = new Set<string>();

		for (const rec of records) {
			const alreadyExists = await this.exists(rec.privateKeyPath);
			const trashItem = trashMap.get(rec.kid);

			if (
				!alreadyExists &&
				trashItem?.trashPemPath &&
				(await this.exists(trashItem.trashPemPath))
			) {
				const destAbs = resolve(rec.privateKeyPath);
				await mkdir(dirname(destAbs), { recursive: true });
				await copyFile(resolve(trashItem.trashPemPath), destAbs);
				await rm(resolve(trashItem.trashPemPath), { force: true });
				restoredPems.push(rec.privateKeyPath);
				restoredKids.add(rec.kid);
			} else if (alreadyExists && trashItem) {
				if (trashItem.trashPemPath && (await this.exists(trashItem.trashPemPath))) {
					await rm(resolve(trashItem.trashPemPath), { force: true });
				}
				restoredKids.add(rec.kid);
			}
		}

		if (restoredKids.size > 0) {
			const remaining = current.filter((x) => !restoredKids.has(x.record.kid));
			await this.writeTrashManifest(remaining);
		}

		return restoredPems;
	}

	/**
	 * Dọn sạch vĩnh viễn Thùng rác (toàn bộ hoặc theo danh sách kid).
	 */
	async emptyTrash(kids?: readonly string[]): Promise<number> {
		const current = await this.readTrashManifest();
		if (current.length === 0) return 0;

		const targetSet = kids && kids.length > 0 ? new Set(kids) : null;
		const toDelete = targetSet ? current.filter((x) => targetSet.has(x.record.kid)) : current;
		const toKeep = targetSet ? current.filter((x) => !targetSet.has(x.record.kid)) : [];

		for (const item of toDelete) {
			if (item.trashPemPath && (await this.exists(item.trashPemPath))) {
				await rm(resolve(item.trashPemPath), { force: true });
			}
		}

		await this.writeTrashManifest(toKeep);
		return toDelete.length;
	}
}
