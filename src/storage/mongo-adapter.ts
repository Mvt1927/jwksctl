import type { Collection, MongoClient } from "mongodb";
import { toCleanPublicJwk } from "../core/crypto.ts";
import { IntegrityViolationError, SafeMutationGuard } from "../core/guard.ts";
import type { JwkRecord, KeyStatus, MutationDiff, PublicJwk } from "../core/types.ts";
import type { IStorageAdapter, RemoveKeysOptions } from "./adapter.ts";

interface MongoKeyDocument {
	_id: string;
	kid: string;
	kty: "RSA" | "EC" | "OKP";
	alg: JwkRecord["alg"];
	use: "sig";
	status: KeyStatus;
	publicJwk: PublicJwk;
	privateKeyPath: string;
	isPrivateKeyEncrypted: boolean;
	createdAt: string;
	expiresAt: string | null;
	rotatedAt: string | null;
}

/**
 * Vá lỗi tương thích Bun 1.3.x với gói `bson` v7 (gọi v8.startupSnapshot.isBuildingSnapshot chưa cài đặt trong Bun).
 */
function ensureBunV8SnapshotCompat(): void {
	try {
		const v8Mod = process.getBuiltinModule?.("v8") as
			{ startupSnapshot?: { isBuildingSnapshot?: () => boolean } } | undefined;
		if (v8Mod?.startupSnapshot) {
			v8Mod.startupSnapshot.isBuildingSnapshot = () => false;
		}
	} catch {
		// Bỏ qua nếu môi trường không cần shim
	}
}

export class MongoAdapter implements IStorageAdapter {
	readonly kind = "mongodb";
	readonly location: string;
	readonly collectionName: string;
	private client: MongoClient | null = null;
	private col: Collection<MongoKeyDocument> | null = null;

	constructor(uri: string, collectionName: string = "jwks_keys") {
		this.location = uri;
		this.collectionName = collectionName;
	}

	private async getCollection(): Promise<Collection<MongoKeyDocument>> {
		if (this.col) return this.col;
		ensureBunV8SnapshotCompat();
		const { MongoClient: DynamicMongoClient } = await import("mongodb");
		this.client = new DynamicMongoClient(this.location);
		await this.client.connect();
		const db = this.client.db();
		this.col = db.collection<MongoKeyDocument>(this.collectionName);
		await this.col.createIndex({ kid: 1 }, { unique: true });
		await this.col.createIndex({ status: 1, expiresAt: 1 });
		return this.col;
	}

	private docToRecord(doc: MongoKeyDocument): JwkRecord {
		return {
			...doc.publicJwk,
			kid: doc.kid,
			kty: doc.kty,
			alg: doc.alg,
			use: "sig",
			status: doc.status,
			privateKeyPath: doc.privateKeyPath,
			isPrivateKeyEncrypted: doc.isPrivateKeyEncrypted,
			createdAt: doc.createdAt,
			expiresAt: doc.expiresAt,
			rotatedAt: doc.rotatedAt,
		};
	}

	private recordToDoc(rec: JwkRecord): MongoKeyDocument {
		return {
			_id: rec.kid,
			kid: rec.kid,
			kty: rec.kty,
			alg: rec.alg,
			use: "sig",
			status: rec.status,
			publicJwk: toCleanPublicJwk(rec),
			privateKeyPath: rec.privateKeyPath,
			isPrivateKeyEncrypted: rec.isPrivateKeyEncrypted,
			createdAt: rec.createdAt,
			expiresAt: rec.expiresAt,
			rotatedAt: rec.rotatedAt,
		};
	}

	async init(): Promise<void> {
		await this.getCollection();
	}

	async listKeys(): Promise<JwkRecord[]> {
		const col = await this.getCollection();
		const docs = await col.find({}).sort({ createdAt: 1, kid: 1 }).toArray();
		const records = docs.map((d) => this.docToRecord(d));
		SafeMutationGuard.assertNoPrivateMaterial(records);
		SafeMutationGuard.assertUniqueKids(records);
		return records;
	}

	async getKey(kid: string): Promise<JwkRecord | null> {
		const col = await this.getCollection();
		const doc = await col.findOne({ kid });
		return doc ? this.docToRecord(doc) : null;
	}

	async addKeys(newRecords: readonly JwkRecord[]): Promise<MutationDiff> {
		const col = await this.getCollection();
		const before = await this.listKeys();
		const after = [...before, ...newRecords];
		const addedKids = newRecords.map((r) => r.kid);

		SafeMutationGuard.verifyCreateInvariant(before, after, addedKids);

		if (newRecords.length > 0) {
			await col.insertMany(newRecords.map((r) => this.recordToDoc(r)));
		}
		return SafeMutationGuard.computeDiff(before, after);
	}

	async updateKeys(updatedRecords: readonly JwkRecord[]): Promise<MutationDiff> {
		const col = await this.getCollection();
		const before = await this.listKeys();
		const updateMap = new Map(updatedRecords.map((r) => [r.kid, r]));
		const targetKids = Array.from(updateMap.keys());

		for (const kid of targetKids) {
			if (!before.some((k) => k.kid === kid)) {
				throw new IntegrityViolationError(
					`Không tìm thấy khóa "${kid}" trong collection "${this.collectionName}" để cập nhật.`,
				);
			}
		}

		const after = before.map((k) => updateMap.get(k.kid) ?? k);
		SafeMutationGuard.verifyUpdateInvariant(before, after, targetKids);

		for (const rec of updatedRecords) {
			const doc = this.recordToDoc(rec);
			await col.replaceOne({ kid: rec.kid }, doc);
		}

		return SafeMutationGuard.computeDiff(before, after);
	}

	async rotateAtomic(
		updatedOldRecords: readonly JwkRecord[],
		newActiveRecord: JwkRecord,
	): Promise<MutationDiff> {
		const col = await this.getCollection();
		const before = await this.listKeys();
		const updateMap = new Map(updatedOldRecords.map((r) => [r.kid, r]));
		const targetOldKids = Array.from(updateMap.keys());

		const intermediate = before.map((k) => updateMap.get(k.kid) ?? k);
		SafeMutationGuard.verifyUpdateInvariant(before, intermediate, targetOldKids);

		const after = [...intermediate, newActiveRecord];
		SafeMutationGuard.verifyCreateInvariant(intermediate, after, [newActiveRecord.kid]);

		for (const oldRec of updatedOldRecords) {
			await col.updateOne(
				{ kid: oldRec.kid },
				{
					$set: {
						status: oldRec.status,
						expiresAt: oldRec.expiresAt,
						rotatedAt: oldRec.rotatedAt,
					},
				},
			);
		}
		await col.insertOne(this.recordToDoc(newActiveRecord));

		return SafeMutationGuard.computeDiff(before, after);
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
		const col = await this.getCollection();
		const before = await this.listKeys();
		const targetSet = new Set(kidsToRemove);
		const after = before.filter((k) => !targetSet.has(k.kid));

		SafeMutationGuard.verifyDeleteInvariant(before, after, kidsToRemove, options);

		await col.deleteMany({ kid: { $in: Array.from(targetSet) } });
		return SafeMutationGuard.computeDiff(before, after);
	}

	async close(): Promise<void> {
		if (this.client) {
			await this.client.close();
			this.client = null;
			this.col = null;
		}
	}
}
