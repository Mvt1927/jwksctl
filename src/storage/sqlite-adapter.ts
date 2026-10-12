import { Database } from "bun:sqlite";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { IntegrityViolationError, SafeMutationGuard } from "../core/guard.ts";
import type { JwkRecord, KeyStatus, MutationDiff, PublicJwk } from "../core/types.ts";
import { toCleanPublicJwk } from "../core/crypto.ts";
import type { IStorageAdapter, RemoveKeysOptions } from "./adapter.ts";

interface SqliteKeyRow {
  kid: string;
  kty: string;
  alg: string;
  use: string;
  status: string;
  public_jwk: string;
  private_key_path: string;
  is_encrypted: number;
  created_at: string;
  expires_at: string | null;
  rotated_at: string | null;
}

function validateTableName(name: string): string {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
    throw new Error(`Tên bảng SQL không hợp lệ: "${name}". Chỉ cho phép chữ cái, số và dấu gạch dưới.`);
  }
  return name;
}

export class SqliteAdapter implements IStorageAdapter {
  readonly kind = "sqlite";
  readonly location: string;
  readonly tableName: string;
  private db: Database | null = null;

  constructor(dbPath: string = "./jwks.sqlite", tableName: string = "jwks_keys") {
    this.location = dbPath === ":memory:" ? ":memory:" : resolve(dbPath.replace(/^sqlite:\/\//, ""));
    this.tableName = validateTableName(tableName);
  }

  private async getDb(): Promise<Database> {
    if (this.db) return this.db;
    if (this.location !== ":memory:") {
      await mkdir(dirname(this.location), { recursive: true });
    }
    this.db = new Database(this.location, { create: true });
    this.db.run("PRAGMA journal_mode = WAL;");
    this.db.run("PRAGMA foreign_keys = ON;");
    this.ensureSchema(this.db);
    return this.db;
  }

  private ensureSchema(db: Database): void {
    db.run(`
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        kid TEXT PRIMARY KEY,
        kty TEXT NOT NULL,
        alg TEXT NOT NULL,
        use TEXT NOT NULL,
        status TEXT NOT NULL,
        public_jwk TEXT NOT NULL,
        private_key_path TEXT NOT NULL,
        is_encrypted INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        rotated_at TEXT
      );
    `);
    db.run(`
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_status_expires
      ON ${this.tableName} (status, expires_at);
    `);
  }

  private rowToRecord(row: SqliteKeyRow): JwkRecord {
    const publicJwk = JSON.parse(row.public_jwk) as PublicJwk;
    return {
      ...publicJwk,
      kid: row.kid,
      kty: row.kty as JwkRecord["kty"],
      alg: row.alg as JwkRecord["alg"],
      use: "sig",
      status: row.status as KeyStatus,
      privateKeyPath: row.private_key_path,
      isPrivateKeyEncrypted: Boolean(row.is_encrypted),
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      rotatedAt: row.rotated_at,
    };
  }

  async init(): Promise<void> {
    await this.getDb();
  }

  async listKeys(): Promise<JwkRecord[]> {
    const db = await this.getDb();
    const stmt = db.query<SqliteKeyRow, []>(
      `SELECT kid, kty, alg, use, status, public_jwk, private_key_path, is_encrypted, created_at, expires_at, rotated_at
       FROM ${this.tableName}
       ORDER BY created_at ASC, rowid ASC`
    );
    try {
      const rows = stmt.all();
      const records = rows.map((r) => this.rowToRecord(r));
      SafeMutationGuard.assertNoPrivateMaterial(records);
      SafeMutationGuard.assertUniqueKids(records);
      return records;
    } finally {
      stmt.finalize();
    }
  }

  async getKey(kid: string): Promise<JwkRecord | null> {
    const db = await this.getDb();
    const stmt = db.query<SqliteKeyRow, [string]>(
      `SELECT kid, kty, alg, use, status, public_jwk, private_key_path, is_encrypted, created_at, expires_at, rotated_at
       FROM ${this.tableName}
       WHERE kid = ?1`
    );
    try {
      const row = stmt.get(kid);
      return row ? this.rowToRecord(row) : null;
    } finally {
      stmt.finalize();
    }
  }

  async addKeys(newRecords: readonly JwkRecord[]): Promise<MutationDiff> {
    const db = await this.getDb();
    const before = await this.listKeys();
    const after = [...before, ...newRecords];
    const addedKids = newRecords.map((r) => r.kid);

    SafeMutationGuard.verifyCreateInvariant(before, after, addedKids);

    const insertStmt = db.prepare(`
      INSERT INTO ${this.tableName} (
        kid, kty, alg, use, status, public_jwk, private_key_path, is_encrypted, created_at, expires_at, rotated_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
    `);

    try {
      const tx = db.transaction((items: readonly JwkRecord[]) => {
        for (const rec of items) {
          const cleanPub = toCleanPublicJwk(rec);
          insertStmt.run(
            rec.kid,
            rec.kty,
            rec.alg,
            rec.use,
            rec.status,
            JSON.stringify(cleanPub),
            rec.privateKeyPath,
            rec.isPrivateKeyEncrypted ? 1 : 0,
            rec.createdAt,
            rec.expiresAt,
            rec.rotatedAt
          );
        }
      });

      tx(newRecords);
    } finally {
      insertStmt.finalize();
    }
    return SafeMutationGuard.computeDiff(before, after);
  }

  async updateKeys(updatedRecords: readonly JwkRecord[]): Promise<MutationDiff> {
    const db = await this.getDb();
    const before = await this.listKeys();
    const updateMap = new Map(updatedRecords.map((r) => [r.kid, r]));
    const targetKids = Array.from(updateMap.keys());

    for (const kid of targetKids) {
      if (!before.some((k) => k.kid === kid)) {
        throw new IntegrityViolationError(
          `Không tìm thấy khóa "${kid}" trong bảng "${this.tableName}" để cập nhật.`
        );
      }
    }

    const after = before.map((k) => updateMap.get(k.kid) ?? k);
    SafeMutationGuard.verifyUpdateInvariant(before, after, targetKids);

    const updateStmt = db.prepare(`
      UPDATE ${this.tableName}
      SET status = ?1,
          public_jwk = ?2,
          private_key_path = ?3,
          is_encrypted = ?4,
          expires_at = ?5,
          rotated_at = ?6
      WHERE kid = ?7
    `);

    try {
      const tx = db.transaction((items: readonly JwkRecord[]) => {
        for (const rec of items) {
          const cleanPub = toCleanPublicJwk(rec);
          updateStmt.run(
            rec.status,
            JSON.stringify(cleanPub),
            rec.privateKeyPath,
            rec.isPrivateKeyEncrypted ? 1 : 0,
            rec.expiresAt,
            rec.rotatedAt,
            rec.kid
          );
        }
      });

      tx(updatedRecords);
    } finally {
      updateStmt.finalize();
    }
    return SafeMutationGuard.computeDiff(before, after);
  }

  async rotateAtomic(
    updatedOldRecords: readonly JwkRecord[],
    newActiveRecord: JwkRecord
  ): Promise<MutationDiff> {
    const db = await this.getDb();
    const before = await this.listKeys();
    const updateMap = new Map(updatedOldRecords.map((r) => [r.kid, r]));
    const targetOldKids = Array.from(updateMap.keys());

    const intermediate = before.map((k) => updateMap.get(k.kid) ?? k);
    SafeMutationGuard.verifyUpdateInvariant(before, intermediate, targetOldKids);

    const after = [...intermediate, newActiveRecord];
    SafeMutationGuard.verifyCreateInvariant(intermediate, after, [newActiveRecord.kid]);

    const updateStmt = db.prepare(`
      UPDATE ${this.tableName}
      SET status = ?1,
          expires_at = ?2,
          rotated_at = ?3
      WHERE kid = ?4
    `);
    const insertStmt = db.prepare(`
      INSERT INTO ${this.tableName} (
        kid, kty, alg, use, status, public_jwk, private_key_path, is_encrypted, created_at, expires_at, rotated_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
    `);

    try {
      const tx = db.transaction(() => {
        for (const oldRec of updatedOldRecords) {
          updateStmt.run(oldRec.status, oldRec.expiresAt, oldRec.rotatedAt, oldRec.kid);
        }
        const cleanPub = toCleanPublicJwk(newActiveRecord);
        insertStmt.run(
          newActiveRecord.kid,
          newActiveRecord.kty,
          newActiveRecord.alg,
          newActiveRecord.use,
          newActiveRecord.status,
          JSON.stringify(cleanPub),
          newActiveRecord.privateKeyPath,
          newActiveRecord.isPrivateKeyEncrypted ? 1 : 0,
          newActiveRecord.createdAt,
          newActiveRecord.expiresAt,
          newActiveRecord.rotatedAt
        );
      });

      tx();
    } finally {
      updateStmt.finalize();
      insertStmt.finalize();
    }
    return SafeMutationGuard.computeDiff(before, after);
  }

  async previewRemoveKeys(
    kidsToRemove: readonly string[],
    options: RemoveKeysOptions = {}
  ): Promise<MutationDiff> {
    const before = await this.listKeys();
    const targetSet = new Set(kidsToRemove);
    const after = before.filter((k) => !targetSet.has(k.kid));

    SafeMutationGuard.verifyDeleteInvariant(before, after, kidsToRemove, options);
    return SafeMutationGuard.computeDiff(before, after);
  }

  async removeKeys(
    kidsToRemove: readonly string[],
    options: RemoveKeysOptions = {}
  ): Promise<MutationDiff> {
    const db = await this.getDb();
    const before = await this.listKeys();
    const targetSet = new Set(kidsToRemove);
    const after = before.filter((k) => !targetSet.has(k.kid));

    SafeMutationGuard.verifyDeleteInvariant(before, after, kidsToRemove, options);

    const deleteStmt = db.prepare(`DELETE FROM ${this.tableName} WHERE kid = ?1`);
    try {
      const tx = db.transaction((kids: readonly string[]) => {
        for (const kid of kids) {
          deleteStmt.run(kid);
        }
      });

      tx(Array.from(targetSet));
    } finally {
      deleteStmt.finalize();
    }
    return SafeMutationGuard.computeDiff(before, after);
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close(false);
      this.db = null;
    }
  }
}
