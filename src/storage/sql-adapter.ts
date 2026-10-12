import { SQL } from "bun";
import { toCleanPublicJwk } from "../core/crypto.ts";
import { IntegrityViolationError, SafeMutationGuard } from "../core/guard.ts";
import type { JwkRecord, KeyStatus, MutationDiff, PublicJwk } from "../core/types.ts";
import type { IStorageAdapter, RemoveKeysOptions } from "./adapter.ts";

interface SqlKeyRow {
	kid: string;
	kty: string;
	alg: string;
	use: string;
	status: string;
	public_jwk: string | PublicJwk;
	private_key_path: string;
	is_encrypted: boolean | number;
	created_at: string | Date;
	expires_at: string | Date | null;
	rotated_at: string | Date | null;
}

function validateTableName(name: string): string {
	if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
		throw new Error(
			`Tên bảng SQL không hợp lệ: "${name}". Chỉ cho phép chữ cái, số và dấu gạch dưới.`,
		);
	}
	return name;
}

function toIsoOrNull(val: string | Date | null | undefined): string | null {
	if (!val) return null;
	if (val instanceof Date) return val.toISOString();
	return String(val);
}

/**
 * Adapter lưu trữ JWKS cho PostgreSQL và MySQL/MariaDB thông qua Bun.SQL.
 */
export class SqlAdapter implements IStorageAdapter {
	readonly kind: "postgres" | "mysql";
	readonly location: string;
	readonly tableName: string;
	private sql: SQL | null = null;
	private initialized = false;

	constructor(
		uri: string,
		kind: "postgres" | "mysql" = "postgres",
		tableName: string = "jwks_keys",
	) {
		this.kind = kind;
		this.location = uri;
		this.tableName = validateTableName(tableName);
	}

	private async getClient(): Promise<SQL> {
		if (!this.sql) {
			this.sql = new SQL(this.location);
		}
		if (!this.initialized) {
			await this.ensureSchema(this.sql);
			this.initialized = true;
		}
		return this.sql;
	}

	private isBooleanColumnSupported(): boolean {
		return this.kind === "postgres" && !this.location.startsWith("sqlite:");
	}

	private async ensureSchema(sql: SQL): Promise<void> {
		if (this.kind === "postgres") {
			const boolType = this.isBooleanColumnSupported()
				? "BOOLEAN NOT NULL DEFAULT FALSE"
				: "INTEGER NOT NULL DEFAULT 0";
			await sql.unsafe(`
        CREATE TABLE IF NOT EXISTS ${this.tableName} (
          kid VARCHAR(191) PRIMARY KEY,
          kty VARCHAR(32) NOT NULL,
          alg VARCHAR(32) NOT NULL,
          use VARCHAR(16) NOT NULL,
          status VARCHAR(32) NOT NULL,
          public_jwk TEXT NOT NULL,
          private_key_path TEXT NOT NULL,
          is_encrypted ${boolType},
          created_at VARCHAR(64) NOT NULL,
          expires_at VARCHAR(64),
          rotated_at VARCHAR(64)
        );
      `);
			await sql.unsafe(`
        CREATE INDEX IF NOT EXISTS idx_${this.tableName}_status_expires
        ON ${this.tableName} (status, expires_at);
      `);
		} else {
			// MySQL / MariaDB
			await sql.unsafe(`
        CREATE TABLE IF NOT EXISTS ${this.tableName} (
          kid VARCHAR(191) PRIMARY KEY,
          kty VARCHAR(32) NOT NULL,
          alg VARCHAR(32) NOT NULL,
          \`use\` VARCHAR(16) NOT NULL,
          status VARCHAR(32) NOT NULL,
          public_jwk TEXT NOT NULL,
          private_key_path TEXT NOT NULL,
          is_encrypted TINYINT(1) NOT NULL DEFAULT 0,
          created_at VARCHAR(64) NOT NULL,
          expires_at VARCHAR(64) NULL,
          rotated_at VARCHAR(64) NULL,
          INDEX idx_${this.tableName}_status_expires (status, expires_at)
        );
      `);
		}
	}

	private rowToRecord(row: SqlKeyRow): JwkRecord {
		const publicJwk: PublicJwk =
			typeof row.public_jwk === "string"
				? (JSON.parse(row.public_jwk) as PublicJwk)
				: row.public_jwk;

		return {
			...publicJwk,
			kid: row.kid,
			kty: row.kty as JwkRecord["kty"],
			alg: row.alg as JwkRecord["alg"],
			use: "sig",
			status: row.status as KeyStatus,
			privateKeyPath: row.private_key_path,
			isPrivateKeyEncrypted: Boolean(row.is_encrypted),
			createdAt: toIsoOrNull(row.created_at) ?? new Date().toISOString(),
			expiresAt: toIsoOrNull(row.expires_at),
			rotatedAt: toIsoOrNull(row.rotated_at),
		};
	}

	async init(): Promise<void> {
		await this.getClient();
	}

	async listKeys(): Promise<JwkRecord[]> {
		const sql = await this.getClient();
		const useCol = this.kind === "mysql" ? "`use`" : "use";
		const rows = (await sql.unsafe(
			`SELECT kid, kty, alg, ${useCol} AS use, status, public_jwk, private_key_path, is_encrypted, created_at, expires_at, rotated_at
       FROM ${this.tableName}
       ORDER BY created_at ASC, kid ASC`,
		)) as SqlKeyRow[];

		const records = rows.map((r) => this.rowToRecord(r));
		SafeMutationGuard.assertNoPrivateMaterial(records);
		SafeMutationGuard.assertUniqueKids(records);
		return records;
	}

	async getKey(kid: string): Promise<JwkRecord | null> {
		const all = await this.listKeys();
		return all.find((k) => k.kid === kid) ?? null;
	}

	async addKeys(newRecords: readonly JwkRecord[]): Promise<MutationDiff> {
		const sql = await this.getClient();
		const before = await this.listKeys();
		const after = [...before, ...newRecords];
		const addedKids = newRecords.map((r) => r.kid);

		SafeMutationGuard.verifyCreateInvariant(before, after, addedKids);

		await sql.begin(async (tx) => {
			for (const rec of newRecords) {
				const cleanPub = JSON.stringify(toCleanPublicJwk(rec));
				const encVal = this.isBooleanColumnSupported()
					? rec.isPrivateKeyEncrypted
					: rec.isPrivateKeyEncrypted
						? 1
						: 0;
				const rowObj = {
					kid: rec.kid,
					kty: rec.kty,
					alg: rec.alg,
					use: rec.use,
					status: rec.status,
					public_jwk: cleanPub,
					private_key_path: rec.privateKeyPath,
					is_encrypted: encVal,
					created_at: rec.createdAt,
					expires_at: rec.expiresAt,
					rotated_at: rec.rotatedAt,
				};
				await tx`INSERT INTO ${sql(this.tableName)} ${sql(rowObj)}`;
			}
		});

		return SafeMutationGuard.computeDiff(before, after);
	}

	async updateKeys(updatedRecords: readonly JwkRecord[]): Promise<MutationDiff> {
		const sql = await this.getClient();
		const before = await this.listKeys();
		const updateMap = new Map(updatedRecords.map((r) => [r.kid, r]));
		const targetKids = Array.from(updateMap.keys());

		for (const kid of targetKids) {
			if (!before.some((k) => k.kid === kid)) {
				throw new IntegrityViolationError(
					`Không tìm thấy khóa "${kid}" trong bảng "${this.tableName}" để cập nhật.`,
				);
			}
		}

		const after = before.map((k) => updateMap.get(k.kid) ?? k);
		SafeMutationGuard.verifyUpdateInvariant(before, after, targetKids);

		await sql.begin(async (tx) => {
			for (const rec of updatedRecords) {
				const cleanPub = JSON.stringify(toCleanPublicJwk(rec));
				const encVal = this.isBooleanColumnSupported()
					? rec.isPrivateKeyEncrypted
					: rec.isPrivateKeyEncrypted
						? 1
						: 0;
				await tx`
          UPDATE ${sql(this.tableName)}
          SET status = ${rec.status},
              public_jwk = ${cleanPub},
              private_key_path = ${rec.privateKeyPath},
              is_encrypted = ${encVal},
              expires_at = ${rec.expiresAt},
              rotated_at = ${rec.rotatedAt}
          WHERE kid = ${rec.kid}
        `;
			}
		});

		return SafeMutationGuard.computeDiff(before, after);
	}

	async rotateAtomic(
		updatedOldRecords: readonly JwkRecord[],
		newActiveRecord: JwkRecord,
	): Promise<MutationDiff> {
		const sql = await this.getClient();
		const before = await this.listKeys();
		const updateMap = new Map(updatedOldRecords.map((r) => [r.kid, r]));
		const targetOldKids = Array.from(updateMap.keys());

		const intermediate = before.map((k) => updateMap.get(k.kid) ?? k);
		SafeMutationGuard.verifyUpdateInvariant(before, intermediate, targetOldKids);

		const after = [...intermediate, newActiveRecord];
		SafeMutationGuard.verifyCreateInvariant(intermediate, after, [newActiveRecord.kid]);

		await sql.begin(async (tx) => {
			for (const oldRec of updatedOldRecords) {
				await tx`
          UPDATE ${sql(this.tableName)}
          SET status = ${oldRec.status},
              expires_at = ${oldRec.expiresAt},
              rotated_at = ${oldRec.rotatedAt}
          WHERE kid = ${oldRec.kid}
        `;
			}

			const cleanPub = JSON.stringify(toCleanPublicJwk(newActiveRecord));
			const encVal = this.isBooleanColumnSupported()
				? newActiveRecord.isPrivateKeyEncrypted
				: newActiveRecord.isPrivateKeyEncrypted
					? 1
					: 0;
			const rowObj = {
				kid: newActiveRecord.kid,
				kty: newActiveRecord.kty,
				alg: newActiveRecord.alg,
				use: newActiveRecord.use,
				status: newActiveRecord.status,
				public_jwk: cleanPub,
				private_key_path: newActiveRecord.privateKeyPath,
				is_encrypted: encVal,
				created_at: newActiveRecord.createdAt,
				expires_at: newActiveRecord.expiresAt,
				rotated_at: newActiveRecord.rotatedAt,
			};
			await tx`INSERT INTO ${sql(this.tableName)} ${sql(rowObj)}`;
		});

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
		const sql = await this.getClient();
		const before = await this.listKeys();
		const targetSet = new Set(kidsToRemove);
		const after = before.filter((k) => !targetSet.has(k.kid));

		SafeMutationGuard.verifyDeleteInvariant(before, after, kidsToRemove, options);

		await sql.begin(async (tx) => {
			for (const kid of targetSet) {
				await tx`DELETE FROM ${sql(this.tableName)} WHERE kid = ${kid}`;
			}
		});

		return SafeMutationGuard.computeDiff(before, after);
	}

	async close(): Promise<void> {
		if (this.sql) {
			await this.sql.close();
			this.sql = null;
			this.initialized = false;
		}
	}
}
