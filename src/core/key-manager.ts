import { decodeProtectedHeader, type JWK, type JWTPayload } from "jose";
import {
  exportPublicJwkToPem,
  extractFromJwkObject,
  extractPublicJwkFromPrivatePem,
  generateKeyMaterial,
  signJwtWithPem,
  toCleanPublicJwk,
  verifyJwtWithPublicJwk,
} from "./crypto.ts";
import { SafeMutationGuard } from "./guard.ts";
import { PemVault } from "./pem-vault.ts";
import type {
  JwkRecord,
  KeyStatus,
  MutationDiff,
  PublicJwksPayload,
  SigningAlgorithm,
} from "./types.ts";
import type { IStorageAdapter } from "../storage/adapter.ts";

/**
 * Phân tích chuỗi thời gian ân hạn (ví dụ: "7d", "24h", "30m", "60s") sang mili-giây.
 */
export function parseDurationMs(durationStr: string): number {
  const match = /^(\d+)\s*(s|m|h|d)$/i.exec(durationStr.trim());
  if (!match) {
    throw new Error(
      `Định dạng thời gian "${durationStr}" không hợp lệ. Ví dụ hợp lệ: "30m", "24h", "7d".`
    );
  }
  const value = Number(match[1]);
  const unit = match[2]!.toLowerCase();
  switch (unit) {
    case "s":
      return value * 1000;
    case "m":
      return value * 60 * 1000;
    case "h":
      return value * 60 * 60 * 1000;
    case "d":
      return value * 24 * 60 * 60 * 1000;
    default:
      throw new Error(`Đơn vị thời gian không hỗ trợ: ${unit}`);
  }
}

export function isRecordExpired(record: JwkRecord, now: Date = new Date()): boolean {
  if (!record.expiresAt) return false;
  return new Date(record.expiresAt).getTime() <= now.getTime();
}

export interface GenerateKeyOptions {
  alg?: SigningAlgorithm;
  kid?: string;
  modulusLength?: number;
  passphrase?: string;
  status?: KeyStatus;
  expiresIn?: string;
}

export interface RotateKeyOptions {
  alg?: SigningAlgorithm;
  kid?: string;
  modulusLength?: number;
  gracePeriod?: string;
  revokeOldImmediately?: boolean;
  passphrase?: string;
}

export interface InspectKeyResult {
  record: JwkRecord;
  privateKeyFileExists: boolean;
  isExpired: boolean;
  publicPem: string;
}

export interface IntegrityCheckReport {
  valid: boolean;
  totalKeys: number;
  activeKeys: number;
  passiveKeys: number;
  revokedKeys: number;
  expiredPassiveKeys: string[];
  missingPrivateKeyFiles: Array<{ kid: string; path: string }>;
}

export class KeyManagerService {
  constructor(
    public readonly adapter: IStorageAdapter,
    public readonly vault: PemVault = new PemVault("./keys")
  ) {}

  async initStore(): Promise<void> {
    await this.adapter.init();
  }

  async listKeys(filter?: { status?: KeyStatus }): Promise<JwkRecord[]> {
    const all = await this.adapter.listKeys();
    if (!filter?.status) return all;
    return all.filter((k) => k.status === filter.status);
  }

  async generateKey(options: GenerateKeyOptions = {}): Promise<{
    record: JwkRecord;
    diff: MutationDiff;
  }> {
    const alg = options.alg ?? "RS256";
    const material = await generateKeyMaterial({
      alg,
      kid: options.kid,
      modulusLength: options.modulusLength,
    });

    const savedPem = await this.vault.savePrivateKey(
      material.kid,
      material.privateKeyPem,
      options.passphrase
    );

    const now = new Date();
    const expiresAt = options.expiresIn
      ? new Date(now.getTime() + parseDurationMs(options.expiresIn)).toISOString()
      : null;

    const record: JwkRecord = {
      ...material.publicJwk,
      status: options.status ?? "active",
      privateKeyPath: savedPem.privateKeyPath,
      isPrivateKeyEncrypted: savedPem.isEncrypted,
      createdAt: now.toISOString(),
      expiresAt,
      rotatedAt: null,
    };

    try {
      const diff = await this.adapter.addKeys([record]);
      return { record, diff };
    } catch (err) {
      // Nếu ghi vào Store thất bại (ví dụ trùng kid), dọn dẹp file .pem vừa tạo
      await this.vault.deletePrivateKey(savedPem.privateKeyPath);
      throw err;
    }
  }

  async inspectKey(kid: string): Promise<InspectKeyResult> {
    const record = await this.adapter.getKey(kid);
    if (!record) {
      throw new Error(`Không tìm thấy khóa có kid "${kid}" trong Store.`);
    }
    const privateKeyFileExists = await this.vault.exists(record.privateKeyPath);
    const publicPem = await exportPublicJwkToPem(record);
    return {
      record,
      privateKeyFileExists,
      isExpired: isRecordExpired(record),
      publicPem,
    };
  }

  async rotateKeys(options: RotateKeyOptions = {}): Promise<{
    newRecord: JwkRecord;
    demotedKids: string[];
    diff: MutationDiff;
  }> {
    const existing = await this.adapter.listKeys();
    const currentActive = existing.filter((k) => k.status === "active");

    // Nếu không truyền alg, kế thừa thuật toán của khóa active gần nhất (hoặc mặc định RS256)
    const alg = options.alg ?? currentActive.at(-1)?.alg ?? "RS256";
    const graceMs = parseDurationMs(options.gracePeriod ?? "7d");
    const now = new Date();
    const nowIso = now.toISOString();
    const passiveExpiresIso = new Date(now.getTime() + graceMs).toISOString();

    const material = await generateKeyMaterial({
      alg,
      kid: options.kid,
      modulusLength: options.modulusLength,
    });

    const savedPem = await this.vault.savePrivateKey(
      material.kid,
      material.privateKeyPem,
      options.passphrase
    );

    const newActiveRecord: JwkRecord = {
      ...material.publicJwk,
      status: "active",
      privateKeyPath: savedPem.privateKeyPath,
      isPrivateKeyEncrypted: savedPem.isEncrypted,
      createdAt: nowIso,
      expiresAt: null,
      rotatedAt: null,
    };

    const updatedOldRecords: JwkRecord[] = currentActive.map((oldKey) => ({
      ...oldKey,
      status: options.revokeOldImmediately ? "revoked" : "passive",
      rotatedAt: nowIso,
      expiresAt: options.revokeOldImmediately ? nowIso : passiveExpiresIso,
    }));

    try {
      const diff = await this.adapter.rotateAtomic(updatedOldRecords, newActiveRecord);
      return {
        newRecord: newActiveRecord,
        demotedKids: updatedOldRecords.map((k) => k.kid),
        diff,
      };
    } catch (err) {
      await this.vault.deletePrivateKey(savedPem.privateKeyPath);
      throw err;
    }
  }

  async previewRemoveKeys(
    kidsToRemove: readonly string[],
    options: { force?: boolean } = {}
  ): Promise<MutationDiff> {
    return this.adapter.previewRemoveKeys(kidsToRemove, options);
  }

  /**
   * Xóa 1 hoặc nhiều khóa khỏi Store (có kiểm tra chống xóa nhầm và tùy chọn xóa file .pem).
   */
  async removeKeys(
    kidsToRemove: readonly string[],
    options: { force?: boolean; deletePrivateKeyFiles?: boolean } = {}
  ): Promise<{ diff: MutationDiff; deletedPemPaths: string[] }> {
    const diff = await this.adapter.removeKeys(kidsToRemove, {
      force: options.force,
    });

    const deletedPemPaths: string[] = [];
    if (options.deletePrivateKeyFiles) {
      for (const removedRec of diff.removed) {
        const deleted = await this.vault.deletePrivateKey(removedRec.privateKeyPath);
        if (deleted) {
          deletedPemPaths.push(removedRec.privateKeyPath);
        }
      }
    }

    return { diff, deletedPemPaths };
  }

  /**
   * Dọn dẹp các khóa đã bị thu hồi (`revoked`) hoặc khóa `passive` đã hết thời gian ân hạn (`expiresAt`).
   */
  async pruneKeys(
    options: { deletePrivateKeyFiles?: boolean; now?: Date } = {}
  ): Promise<{ diff: MutationDiff; prunedKids: string[]; deletedPemPaths: string[] }> {
    const now = options.now ?? new Date();
    const all = await this.adapter.listKeys();
    const targets = all.filter(
      (k) => k.status === "revoked" || (k.status === "passive" && isRecordExpired(k, now))
    );

    if (targets.length === 0) {
      return {
        diff: SafeMutationGuard.computeDiff(all, all),
        prunedKids: [],
        deletedPemPaths: [],
      };
    }

    const targetKids = targets.map((k) => k.kid);
    const { diff, deletedPemPaths } = await this.removeKeys(targetKids, {
      force: false,
      deletePrivateKeyFiles: options.deletePrivateKeyFiles,
    });

    return {
      diff,
      prunedKids: targetKids,
      deletedPemPaths,
    };
  }

  /**
   * Xuất bộ Public JWKS chuẩn RFC 7517 thuần khiết (lọc bỏ khóa revoked/expired và mọi trường nội bộ).
   */
  async exportPublicJwks(options: { includePassive?: boolean; now?: Date } = {}): Promise<PublicJwksPayload> {
    const includePassive = options.includePassive ?? true;
    const now = options.now ?? new Date();
    const all = await this.adapter.listKeys();

    const eligible = all.filter((rec) => {
      if (rec.status === "active") return true;
      if (includePassive && rec.status === "passive" && !isRecordExpired(rec, now)) {
        return true;
      }
      return false;
    });

    return {
      keys: eligible.map((rec) => toCleanPublicJwk(rec)),
    };
  }

  /**
   * Import khóa từ chuỗi PEM (PKCS#8) hoặc đối tượng JWK bên ngoài vào Store.
   */
  async importKey(options: {
    rawContent: string;
    alg?: SigningAlgorithm;
    kid?: string;
    passphrase?: string;
    status?: KeyStatus;
  }): Promise<{ record: JwkRecord; diff: MutationDiff }> {
    const trimmed = options.rawContent.trim();
    let material;

    if (trimmed.startsWith("-----BEGIN")) {
      if (!options.alg) {
        throw new Error("Khi import từ file PEM, vui lòng chỉ định thuật toán qua --alg (ví dụ: RS256, ES256, EdDSA).");
      }
      material = await extractPublicJwkFromPrivatePem(trimmed, options.alg, options.kid);
    } else {
      const parsed = JSON.parse(trimmed) as JWK;
      material = await extractFromJwkObject(parsed, options.alg, options.kid);
    }

    const savedPem = await this.vault.savePrivateKey(
      material.kid,
      material.privateKeyPem,
      options.passphrase
    );

    const record: JwkRecord = {
      ...material.publicJwk,
      status: options.status ?? "active",
      privateKeyPath: savedPem.privateKeyPath,
      isPrivateKeyEncrypted: savedPem.isEncrypted,
      createdAt: new Date().toISOString(),
      expiresAt: null,
      rotatedAt: null,
    };

    try {
      const diff = await this.adapter.addKeys([record]);
      return { record, diff };
    } catch (err) {
      await this.vault.deletePrivateKey(savedPem.privateKeyPath);
      throw err;
    }
  }

  /**
   * Ký thử JWT bằng khóa `active` (hoặc khóa chỉ định qua `kid`), đọc Private Key từ `privateKeyPath`.
   */
  async signJwt(options: {
    payload: JWTPayload;
    kid?: string;
    expiresIn?: string;
    issuer?: string;
    audience?: string;
    subject?: string;
    passphrase?: string;
  }): Promise<{ token: string; usedKey: JwkRecord }> {
    const all = await this.adapter.listKeys();
    let targetKey: JwkRecord | undefined;

    if (options.kid) {
      targetKey = all.find((k) => k.kid === options.kid);
      if (!targetKey) {
        throw new Error(`Không tìm thấy khóa với kid "${options.kid}".`);
      }
    } else {
      const activeKeys = all.filter((k) => k.status === "active");
      targetKey = activeKeys.at(-1);
      if (!targetKey) {
        throw new Error("Không có khóa nào đang ở trạng thái 'active' để ký JWT.");
      }
    }

    const privateKeyPem = await this.vault.loadPrivateKey(
      targetKey.privateKeyPath,
      options.passphrase
    );

    const token = await signJwtWithPem({
      privateKeyPem,
      alg: targetKey.alg,
      kid: targetKey.kid,
      payload: options.payload,
      expiresIn: options.expiresIn,
      issuer: options.issuer,
      audience: options.audience,
      subject: options.subject,
    });

    return { token, usedKey: targetKey };
  }

  /**
   * Xác thực thử JWT bằng Public JWK trong Store (chỉ chấp nhận khóa `active` hoặc `passive` chưa hết hạn).
   */
  async verifyJwt(
    token: string,
    options: { kid?: string; allowRevokedOrExpiredKey?: boolean } = {}
  ): Promise<{
    payload: JWTPayload;
    protectedHeader: Record<string, unknown>;
    matchedKey: JwkRecord;
  }> {
    const header = decodeProtectedHeader(token);
    const resolvedKid = options.kid ?? header.kid;
    if (!resolvedKid) {
      throw new Error("JWT không chứa 'kid' trong Header và không có --kid được truyền vào.");
    }

    const matchedKey = await this.adapter.getKey(resolvedKid);
    if (!matchedKey) {
      throw new Error(`Không tìm thấy khóa có kid "${resolvedKid}" trong Store.`);
    }

    if (!options.allowRevokedOrExpiredKey) {
      if (matchedKey.status === "revoked") {
        throw new Error(`Khóa "${resolvedKid}" đã bị thu hồi (revoked).`);
      }
      if (matchedKey.status === "passive" && isRecordExpired(matchedKey)) {
        throw new Error(
          `Khóa passive "${resolvedKid}" đã hết thời gian ân hạn vào lúc ${matchedKey.expiresAt}.`
        );
      }
    }

    const verified = await verifyJwtWithPublicJwk(token, matchedKey);
    return {
      ...verified,
      matchedKey,
    };
  }

  /**
   * Kiểm tra toàn diện tính toàn vẹn của Store và sự tồn tại của các file Private Key (.pem).
   */
  async checkIntegrity(now: Date = new Date()): Promise<IntegrityCheckReport> {
    const records = await this.adapter.listKeys();
    const missingPrivateKeyFiles: Array<{ kid: string; path: string }> = [];
    const expiredPassiveKeys: string[] = [];

    let activeKeys = 0;
    let passiveKeys = 0;
    let revokedKeys = 0;

    for (const rec of records) {
      if (rec.status === "active") activeKeys++;
      else if (rec.status === "passive") {
        passiveKeys++;
        if (isRecordExpired(rec, now)) {
          expiredPassiveKeys.push(rec.kid);
        }
      } else if (rec.status === "revoked") {
        revokedKeys++;
      }

      const exists = await this.vault.exists(rec.privateKeyPath);
      if (!exists) {
        missingPrivateKeyFiles.push({ kid: rec.kid, path: rec.privateKeyPath });
      }
    }

    return {
      valid: missingPrivateKeyFiles.length === 0 && activeKeys > 0,
      totalKeys: records.length,
      activeKeys,
      passiveKeys,
      revokedKeys,
      expiredPassiveKeys,
      missingPrivateKeyFiles,
    };
  }

  /**
   * Đồng bộ các khóa từ Store hiện tại sang Store đích (bảo toàn khóa hiện có ở đích và cập nhật khóa trùng kid).
   */
  async syncTo(targetAdapter: IStorageAdapter): Promise<{
    addedCount: number;
    updatedCount: number;
  }> {
    await targetAdapter.init();
    const sourceKeys = await this.adapter.listKeys();
    const targetKeys = await targetAdapter.listKeys();
    const targetMap = new Map(targetKeys.map((k) => [k.kid, k]));

    const toAdd: JwkRecord[] = [];
    const toUpdate: JwkRecord[] = [];

    for (const srcKey of sourceKeys) {
      if (!targetMap.has(srcKey.kid)) {
        toAdd.push(srcKey);
      } else {
        toUpdate.push(srcKey);
      }
    }

    if (toUpdate.length > 0) {
      await targetAdapter.updateKeys(toUpdate);
    }
    if (toAdd.length > 0) {
      await targetAdapter.addKeys(toAdd);
    }

    return {
      addedCount: toAdd.length,
      updatedCount: toUpdate.length,
    };
  }
}
