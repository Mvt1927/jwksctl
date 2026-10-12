import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createStorageAdapter, detectStoreType } from "../src/config/loader.ts";
import { KeyManagerService } from "../src/core/key-manager.ts";
import { PemVault } from "../src/core/pem-vault.ts";
import { MongoAdapter } from "../src/storage/mongo-adapter.ts";
import { SqlAdapter } from "../src/storage/sql-adapter.ts";

describe("Phase 3: Database Adapters (SqlAdapter, MongoAdapter) & JWKS HTTP Server", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await mkdtemp(join(tmpdir(), "jwksctl-p3-test-"));
	});

	afterEach(async () => {
		await rm(tempDir, { recursive: true, force: true });
	});

	test("1. Nhận diện đúng StoreType và khởi tạo SqlAdapter (Postgres/MySQL) & MongoAdapter", () => {
		expect(detectStoreType("postgres://user:pass@localhost:5432/auth")).toBe("postgres");
		expect(detectStoreType("mysql://root@localhost:3306/auth")).toBe("mysql");
		expect(detectStoreType("mongodb://localhost:27017/auth")).toBe("mongodb");
		expect(detectStoreType("sqlite://./local.db")).toBe("sqlite");
		expect(detectStoreType("./jwks.json")).toBe("file");

		const pgAdapter = createStorageAdapter({
			type: "postgres",
			uri: "postgres://user:pass@localhost:5432/auth",
			tableName: "custom_jwks",
		});
		expect(pgAdapter).toBeInstanceOf(SqlAdapter);
		expect(pgAdapter.kind).toBe("postgres");

		const mysqlAdapter = createStorageAdapter({
			type: "mysql",
			uri: "mysql://user:pass@localhost:3306/auth",
		});
		expect(mysqlAdapter).toBeInstanceOf(SqlAdapter);
		expect(mysqlAdapter.kind).toBe("mysql");

		const mongoAdapter = createStorageAdapter({
			type: "mongodb",
			uri: "mongodb://localhost:27017/auth",
		});
		expect(mongoAdapter).toBeInstanceOf(MongoAdapter);
		expect(mongoAdapter.kind).toBe("mongodb");
	});

	test("2. SqlAdapter (Bun.SQL) thực thi trọn vẹn CRUD, Rotate và SafeMutationGuard", async () => {
		const keysDir = join(tempDir, "keys");
		const sqlAdapter = new SqlAdapter("sqlite://:memory:", "postgres", "jwks_sql_test");
		const vault = new PemVault(keysDir);
		const manager = new KeyManagerService(sqlAdapter, vault);

		try {
			await manager.initStore();

			const { record: k1 } = await manager.generateKey({
				alg: "EdDSA",
				kid: "sql-k1",
				status: "passive",
			});
			const { record: k2 } = await manager.generateKey({
				alg: "ES256",
				kid: "sql-k2",
				status: "active",
			});

			expect((await manager.listKeys()).map((k) => k.kid)).toEqual([k1.kid, k2.kid]);

			// Rotate khóa trong SqlAdapter
			const { newRecord: k3, demotedKids } = await manager.rotateKeys({
				alg: "EdDSA",
				kid: "sql-k3",
				gracePeriod: "7d",
			});
			expect(demotedKids).toEqual(["sql-k2"]);
			expect(k3.status).toBe("active");

			// Xóa khóa passive sql-k1, bảo toàn sql-k2 và sql-k3
			const { diff } = await manager.removeKeys(["sql-k1"]);
			expect(diff.beforeCount).toBe(3);
			expect(diff.afterCount).toBe(2);
			expect((await manager.listKeys()).map((k) => k.kid)).toEqual(["sql-k2", "sql-k3"]);
		} finally {
			await sqlAdapter.close();
		}
	});

	test("3. HTTP Server (/.well-known/jwks.json & /health) phục vụ đúng chuẩn RFC 7517", async () => {
		const jwksFile = join(tempDir, "jwks.json");
		const keysDir = join(tempDir, "keys");
		const adapter = createStorageAdapter({ type: "file", uri: jwksFile });
		const vault = new PemVault(keysDir);
		const manager = new KeyManagerService(adapter, vault);

		await manager.initStore();
		await manager.generateKey({ alg: "EdDSA", kid: "serve-k1" });

		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			async fetch(req) {
				const url = new URL(req.url);
				if (url.pathname === "/.well-known/jwks.json") {
					const payload = await manager.exportPublicJwks();
					return Response.json(payload);
				}
				if (url.pathname === "/health") {
					const report = await manager.checkIntegrity();
					return Response.json(report, { status: report.valid ? 200 : 503 });
				}
				return new Response("Not Found", { status: 404 });
			},
		});

		try {
			const jwksRes = await fetch(`http://127.0.0.1:${server.port}/.well-known/jwks.json`);
			expect(jwksRes.status).toBe(200);
			const jwksBody = (await jwksRes.json()) as { keys: Array<Record<string, unknown>> };
			expect(jwksBody.keys.length).toBe(1);
			expect(jwksBody.keys[0]!.kid).toBe("serve-k1");
			expect(jwksBody.keys[0]!.privateKeyPath).toBeUndefined();
			expect(jwksBody.keys[0]!.d).toBeUndefined();

			const healthRes = await fetch(`http://127.0.0.1:${server.port}/health`);
			expect(healthRes.status).toBe(200);
			const healthBody = (await healthRes.json()) as { valid: boolean; activeKeys: number };
			expect(healthBody.valid).toBe(true);
			expect(healthBody.activeKeys).toBe(1);
		} finally {
			await server.stop(true);
		}
	});
});
