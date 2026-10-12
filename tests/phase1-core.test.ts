import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	ActiveKeyDeletionError,
	IntegrityViolationError,
	SafeMutationGuard,
	SecurityViolationError,
} from "../src/core/guard.ts";
import { KeyManagerService } from "../src/core/key-manager.ts";
import { PemVault } from "../src/core/pem-vault.ts";
import { FORBIDDEN_PRIVATE_JWK_FIELDS, type JwkRecord } from "../src/core/types.ts";
import { JsonFileAdapter } from "../src/storage/file-adapter.ts";
import { SqliteAdapter } from "../src/storage/sqlite-adapter.ts";

describe("Phase 1: Core Crypto, SafeMutationGuard, JsonFileAdapter & SqliteAdapter", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await mkdtemp(join(tmpdir(), "jwksctl-test-"));
	});

	afterEach(async () => {
		await rm(tempDir, { recursive: true, force: true });
	});

	test("1. Chỉ lưu Public JWK và privateKeyPath trong jwks.json; mã hóa AES-256-GCM cho file .pem", async () => {
		const jwksPath = join(tempDir, "jwks.json");
		const keysDir = join(tempDir, "keys");
		const adapter = new JsonFileAdapter(jwksPath);
		const vault = new PemVault(keysDir);
		const manager = new KeyManagerService(adapter, vault);

		await manager.initStore();
		const { record } = await manager.generateKey({
			alg: "ES256",
			kid: "test-es256-1",
			passphrase: "super-secret-passphrase",
		});

		expect(record.kid).toBe("test-es256-1");
		expect(record.isPrivateKeyEncrypted).toBe(true);
		expect(await vault.exists(record.privateKeyPath)).toBe(true);

		// Đảm bảo trong jwks.json tuyệt đối không có bất kỳ trường khóa bí mật nào
		const rawFile = JSON.parse(await Bun.file(jwksPath).text());
		const storedKey = rawFile.keys[0];
		for (const field of FORBIDDEN_PRIVATE_JWK_FIELDS) {
			expect(storedKey[field]).toBeUndefined();
		}

		// Kiểm tra file .pem trên đĩa đã được mã hóa AES-256-GCM
		const rawPemOnDisk = await Bun.file(record.privateKeyPath).text();
		expect(rawPemOnDisk).toContain("-----BEGIN ENCRYPTED JWKSCTL PRIVATE KEY-----");

		// Sai passphrase phải báo lỗi
		await expect(vault.loadPrivateKey(record.privateKeyPath, "wrong-pass")).rejects.toThrow(
			"Giải mã Private Key thất bại",
		);

		// Đúng passphrase giải mã ra PKCS#8 chuẩn
		const decryptedPem = await vault.loadPrivateKey(
			record.privateKeyPath,
			"super-secret-passphrase",
		);
		expect(decryptedPem).toContain("-----BEGIN PRIVATE KEY-----");
	});

	test("2. SafeMutationGuard: Chống mất key khi Create/Update, xóa chọn lọc nhiều key và khôi phục từ .bak", async () => {
		const jwksPath = join(tempDir, "jwks.json");
		const keysDir = join(tempDir, "keys");
		const adapter = new JsonFileAdapter(jwksPath);
		const vault = new PemVault(keysDir);
		const manager = new KeyManagerService(adapter, vault);

		await manager.initStore();

		// Tạo 4 khóa: 3 passive và 1 active
		const k1 = (await manager.generateKey({ alg: "EdDSA", kid: "k-1", status: "passive" })).record;
		const k2 = (await manager.generateKey({ alg: "EdDSA", kid: "k-2", status: "passive" })).record;
		const k3 = (await manager.generateKey({ alg: "EdDSA", kid: "k-3", status: "revoked" })).record;
		const k4 = (await manager.generateKey({ alg: "EdDSA", kid: "k-4", status: "active" })).record;

		const allBefore = await manager.listKeys();
		expect(allBefore.map((k) => k.kid)).toEqual(["k-1", "k-2", "k-3", "k-4"]);

		// Chặn xóa nhầm khóa đang active ("k-4") khi không có force
		await expect(manager.removeKeys(["k-4"])).rejects.toBeInstanceOf(ActiveKeyDeletionError);
		expect((await manager.listKeys()).length).toBe(4);

		// Xóa cùng lúc 2 khóa ("k-1" và "k-3") trong file jwks.json
		const preview = await manager.previewRemoveKeys(["k-1", "k-3"]);
		expect(preview.removed.map((k) => k.kid)).toEqual(["k-1", "k-3"]);
		expect(preview.unchangedCount).toBe(2);

		const { diff } = await manager.removeKeys(["k-1", "k-3"], {
			deletePrivateKeyFiles: false,
		});
		expect(diff.beforeCount).toBe(4);
		expect(diff.afterCount).toBe(2);

		// Đảm bảo "k-2" và "k-4" còn nguyên vẹn 100%
		const remaining = await manager.listKeys();
		expect(remaining.map((k) => k.kid)).toEqual(["k-2", "k-4"]);
		expect(remaining[0]).toEqual(k2);
		expect(remaining[1]).toEqual(k4);

		// Khôi phục từ file .bak -> lấy lại đủ 4 khóa
		const restored = await adapter.restoreBackup();
		expect(restored.map((k) => k.kid)).toEqual([k1.kid, k2.kid, k3.kid, k4.kid]);
	});

	test("3. SafeMutationGuard chặn ngay lập tức nếu có thành phần private key hoặc làm rơi key cũ", () => {
		const dummyRecord: JwkRecord = {
			kty: "OKP",
			crv: "Ed25519",
			x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			kid: "safe-1",
			use: "sig",
			alg: "EdDSA",
			status: "active",
			privateKeyPath: "./keys/safe-1.pem",
			isPrivateKeyEncrypted: false,
			createdAt: new Date().toISOString(),
			expiresAt: null,
			rotatedAt: null,
		};

		const leakedRecord = {
			...dummyRecord,
			kid: "leaked-2",
			d: "secret-private-scalar",
		} as unknown as JwkRecord;

		expect(() => SafeMutationGuard.assertNoPrivateMaterial([leakedRecord])).toThrow(
			SecurityViolationError,
		);

		// Giả lập lỗi làm rơi key cũ khi CREATE
		const newRecord: JwkRecord = { ...dummyRecord, kid: "safe-2" };
		expect(() =>
			SafeMutationGuard.verifyCreateInvariant([dummyRecord], [newRecord], ["safe-2"]),
		).toThrow(IntegrityViolationError);
	});

	test("4. SqliteAdapter + Vòng đời Rotate -> Sign -> Verify -> Export -> Sync", async () => {
		const sqlitePath = join(tempDir, "jwks.sqlite");
		const jwksFilePath = join(tempDir, "exported-sync.json");
		const keysDir = join(tempDir, "keys");

		const sqliteAdapter = new SqliteAdapter(sqlitePath);
		const fileAdapter = new JsonFileAdapter(jwksFilePath);
		const vault = new PemVault(keysDir);
		const manager = new KeyManagerService(sqliteAdapter, vault);

		await manager.initStore();

		// Tạo khóa đầu tiên (EdDSA) và ký token 1
		const { record: key1 } = await manager.generateKey({ alg: "EdDSA", kid: "key-v1" });
		const { token: token1 } = await manager.signJwt({
			payload: { sub: "user-123", role: "admin" },
			expiresIn: "1h",
		});

		// Xoay vòng khóa sang key-v2 (key-v1 chuyển sang passive với thời gian ân hạn 7d)
		const { newRecord: key2, demotedKids } = await manager.rotateKeys({
			alg: "ES256",
			kid: "key-v2",
			gracePeriod: "7d",
		});
		expect(demotedKids).toEqual(["key-v1"]);
		expect(key2.status).toBe("active");

		// Token 1 (ký bằng key-v1 đang passive) vẫn phải verify thành công!
		const verified1 = await manager.verifyJwt(token1);
		expect(verified1.payload.sub).toBe("user-123");
		expect(verified1.matchedKey.kid).toBe("key-v1");
		expect(verified1.matchedKey.status).toBe("passive");

		// Token 2 mới sẽ tự động ký bằng key-v2 (active)
		const { token: token2, usedKey } = await manager.signJwt({
			payload: { sub: "user-456" },
			expiresIn: "1h",
		});
		expect(usedKey.kid).toBe("key-v2");
		const verified2 = await manager.verifyJwt(token2);
		expect(verified2.payload.sub).toBe("user-456");

		// Xuất Public JWKS chuẩn RFC 7517: phải có đủ 2 khóa và sạch bóng metadata nội bộ
		const exported = await manager.exportPublicJwks();
		expect(exported.keys.length).toBe(2);
		for (const pubKey of exported.keys) {
			const rawPub = pubKey as unknown as Record<string, unknown>;
			expect(rawPub.status).toBeUndefined();
			expect(rawPub.privateKeyPath).toBeUndefined();
			expect(rawPub.createdAt).toBeUndefined();
		}

		// Đồng bộ từ SQLite sang File JSON
		const syncResult = await manager.syncTo(fileAdapter);
		expect(syncResult.addedCount).toBe(2);
		const syncedFileKeys = await fileAdapter.listKeys();
		expect(syncedFileKeys.map((k) => k.kid)).toEqual([key1.kid, key2.kid]);

		await sqliteAdapter.close();
	});
});
