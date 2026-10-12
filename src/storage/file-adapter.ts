import { copyFile, mkdir, rename } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { IntegrityViolationError, SafeMutationGuard } from "../core/guard.ts";
import type { JwkRecord, JwksFilePayload, MutationDiff } from "../core/types.ts";
import type { IStorageAdapter, RemoveKeysOptions } from "./adapter.ts";

export class JsonFileAdapter implements IStorageAdapter {
	readonly kind = "file";
	readonly location: string;
	readonly backupLocation: string;

	constructor(filePath: string = "./jwks.json") {
		this.location = resolve(filePath);
		this.backupLocation = `${this.location}.bak`;
	}

	async init(): Promise<void> {
		const file = Bun.file(this.location);
		if (await file.exists()) {
			// Đọc kiểm tra tính hợp lệ của file hiện có, tuyệt đối không ghi đè làm mất key cũ
			await this.listKeys();
			return;
		}
		await mkdir(dirname(this.location), { recursive: true });
		await this.atomicWrite({ keys: [] }, false);
	}

	async listKeys(): Promise<JwkRecord[]> {
		const file = Bun.file(this.location);
		if (!(await file.exists())) {
			return [];
		}

		const rawText = await file.text();
		let parsed: unknown;
		try {
			parsed = JSON.parse(rawText);
		} catch (err) {
			throw new IntegrityViolationError(
				`File JWKS tại "${this.location}" không phải JSON hợp lệ: ${(err as Error).message}`,
			);
		}

		if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as JwksFilePayload).keys)) {
			throw new IntegrityViolationError(
				`File JWKS tại "${this.location}" sai cấu trúc chuẩn RFC 7517 (thiếu mảng "keys").`,
			);
		}

		const records = (parsed as JwksFilePayload).keys;
		SafeMutationGuard.assertNoPrivateMaterial(records);
		SafeMutationGuard.assertUniqueKids(records);
		return records;
	}

	async getKey(kid: string): Promise<JwkRecord | null> {
		const keys = await this.listKeys();
		return keys.find((k) => k.kid === kid) ?? null;
	}

	async addKeys(newRecords: readonly JwkRecord[]): Promise<MutationDiff> {
		if (newRecords.length === 0) {
			const current = await this.listKeys();
			return SafeMutationGuard.computeDiff(current, current);
		}

		const before = await this.listKeys();
		const after = [...before, ...newRecords];
		const addedKids = newRecords.map((r) => r.kid);

		SafeMutationGuard.verifyCreateInvariant(before, after, addedKids);
		const diff = SafeMutationGuard.computeDiff(before, after);

		await this.atomicWrite({ keys: after }, before.length > 0);
		return diff;
	}

	async updateKeys(updatedRecords: readonly JwkRecord[]): Promise<MutationDiff> {
		const before = await this.listKeys();
		const updateMap = new Map(updatedRecords.map((r) => [r.kid, r]));
		const targetKids = Array.from(updateMap.keys());

		for (const kid of targetKids) {
			if (!before.some((k) => k.kid === kid)) {
				throw new IntegrityViolationError(
					`Không tìm thấy khóa "${kid}" trong "${this.location}" để cập nhật.`,
				);
			}
		}

		const after = before.map((k) => updateMap.get(k.kid) ?? k);
		SafeMutationGuard.verifyUpdateInvariant(before, after, targetKids);
		const diff = SafeMutationGuard.computeDiff(before, after);

		await this.atomicWrite({ keys: after }, true);
		return diff;
	}

	async rotateAtomic(
		updatedOldRecords: readonly JwkRecord[],
		newActiveRecord: JwkRecord,
	): Promise<MutationDiff> {
		const before = await this.listKeys();
		const updateMap = new Map(updatedOldRecords.map((r) => [r.kid, r]));
		const targetOldKids = Array.from(updateMap.keys());

		// Bước 1: Kiểm tra tính toàn vẹn của bước cập nhật khóa cũ
		const intermediate = before.map((k) => updateMap.get(k.kid) ?? k);
		SafeMutationGuard.verifyUpdateInvariant(before, intermediate, targetOldKids);

		// Bước 2: Kiểm tra tính toàn vẹn của bước thêm khóa active mới
		const after = [...intermediate, newActiveRecord];
		SafeMutationGuard.verifyCreateInvariant(intermediate, after, [newActiveRecord.kid]);

		const diff = SafeMutationGuard.computeDiff(before, after);
		await this.atomicWrite({ keys: after }, before.length > 0);
		return diff;
	}

	async previewRemoveKeys(
		kidsToRemove: readonly string[],
		options: RemoveKeysOptions = {},
	): Promise<MutationDiff> {
		const before = await this.listKeys();
		const targetSet = new Set(kidsToRemove);
		const after = before.filter((k) => !targetSet.has(k.kid));

		SafeMutationGuard.verifyDeleteInvariant(before, after, kidsToRemove, options);
		return SafeMutationGuard.computeDiff(before, after);
	}

	async removeKeys(
		kidsToRemove: readonly string[],
		options: RemoveKeysOptions = {},
	): Promise<MutationDiff> {
		const before = await this.listKeys();
		const targetSet = new Set(kidsToRemove);
		const after = before.filter((k) => !targetSet.has(k.kid));

		SafeMutationGuard.verifyDeleteInvariant(before, after, kidsToRemove, options);
		const diff = SafeMutationGuard.computeDiff(before, after);

		await this.atomicWrite({ keys: after }, true);
		return diff;
	}

	async restoreBackup(): Promise<JwkRecord[]> {
		const bakFile = Bun.file(this.backupLocation);
		if (!(await bakFile.exists())) {
			throw new Error(`Không tìm thấy file sao lưu tại "${this.backupLocation}".`);
		}

		const rawText = await bakFile.text();
		const parsed = JSON.parse(rawText) as JwksFilePayload;
		if (!parsed || !Array.isArray(parsed.keys)) {
			throw new IntegrityViolationError("File sao lưu (.bak) không hợp lệ.");
		}

		SafeMutationGuard.assertNoPrivateMaterial(parsed.keys);
		SafeMutationGuard.assertUniqueKids(parsed.keys);

		await this.atomicWrite({ keys: parsed.keys }, false);
		return parsed.keys;
	}

	private async atomicWrite(payload: JwksFilePayload, createBackup: boolean): Promise<void> {
		await mkdir(dirname(this.location), { recursive: true });
		const currentFile = Bun.file(this.location);
		if (createBackup && (await currentFile.exists())) {
			await copyFile(this.location, this.backupLocation);
		}

		const tmpPath = `${this.location}.tmp.${process.pid}.${Date.now()}`;
		const formattedJson = `${JSON.stringify(payload, null, 2)}\n`;
		await Bun.write(tmpPath, formattedJson);
		await rename(tmpPath, this.location);
	}
}
