import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCliProgram } from "../src/cli/program.ts";
import { KeyManagerService } from "../src/core/key-manager.ts";
import { PemVault } from "../src/core/pem-vault.ts";
import { JsonFileAdapter } from "../src/storage/file-adapter.ts";
import { SqliteAdapter } from "../src/storage/sqlite-adapter.ts";

async function runCli(args: string[]): Promise<{ stdout: string }> {
	const logs: string[] = [];
	const origLog = console.log;
	const origWrite = process.stdout.write.bind(process.stdout);

	console.log = (...items: unknown[]) => {
		logs.push(items.map((x) => String(x)).join(" "));
	};
	process.stdout.write = ((chunk: string | Uint8Array) => {
		logs.push(typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk));
		return true;
	}) as typeof process.stdout.write;

	try {
		const program = buildCliProgram();
		program.exitOverride();
		await program.parseAsync(["node", "jwksctl", ...args]);
		return { stdout: logs.join("\n").trim() };
	} finally {
		console.log = origLog;
		process.stdout.write = origWrite;
	}
}

describe("Trash Bin (.trash) & Full Restore (JWK + .pem)", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await mkdtemp(join(tmpdir(), "jwksctl-trash-test-"));
	});

	afterEach(async () => {
		await rm(tempDir, { recursive: true, force: true });
	});

	test("1. Xóa khóa đưa cả JWK và file .pem vào .trash; restore khôi phục lại cả file .pem và ký JWT hoạt động bình thường", async () => {
		const sqlitePath = join(tempDir, "jwks.sqlite");
		const keysDir = join(tempDir, "keys");
		const adapter = new SqliteAdapter(sqlitePath);
		const vault = new PemVault(keysDir);
		const manager = new KeyManagerService(adapter, vault);

		await manager.initStore();

		const { record: k1 } = await manager.generateKey({
			alg: "EdDSA",
			kid: "trash-k1",
			status: "passive",
		});
		const { record: k2 } = await manager.generateKey({
			alg: "ES256",
			kid: "trash-k2",
			status: "active",
		});

		expect(await vault.exists(k1.privateKeyPath)).toBe(true);
		expect(await vault.exists(k2.privateKeyPath)).toBe(true);

		// Xóa cả 2 khóa (mặc định đưa vào Thùng rác ./keys/.trash)
		const removeRes = await manager.removeKeys(["trash-k1", "trash-k2"], { force: true });
		expect(removeRes.trashedItems.length).toBe(2);

		// File .pem gốc trong ./keys đã được chuyển sang ./keys/.trash
		expect(await vault.exists(k1.privateKeyPath)).toBe(false);
		expect(await vault.exists(k2.privateKeyPath)).toBe(false);

		const trashList = await manager.listTrash();
		expect(trashList.map((x) => x.record.kid)).toEqual(["trash-k1", "trash-k2"]);
		expect(trashList[0]!.trashPemPath).not.toBeNull();
		expect(await vault.exists(trashList[0]!.trashPemPath!)).toBe(true);

		// Khôi phục lại khóa "trash-k2" từ Thùng rác (kể cả trên SQLite DB không có file .bak)
		const restoreRes = await manager.restoreKeys({ kids: ["trash-k2"] });
		expect(restoreRes.mode).toBe("trash");
		expect(restoreRes.restoredRecords.map((r) => r.kid)).toEqual(["trash-k2"]);
		expect(restoreRes.restoredPemPaths).toEqual([k2.privateKeyPath]);

		// Kiểm tra file .pem của trash-k2 đã trở lại đúng vị trí ./keys/trash-k2.pem
		expect(await vault.exists(k2.privateKeyPath)).toBe(true);

		// Ký và xác thực JWT bằng khóa vừa restore để chứng minh file .pem nguyên vẹn 100%
		const { token } = await manager.signJwt({
			kid: "trash-k2",
			payload: { sub: "restored-user" },
		});
		const verified = await manager.verifyJwt(token);
		expect(verified.payload.sub).toBe("restored-user");

		// Trong Thùng rác lúc này chỉ còn lại "trash-k1"
		expect((await manager.listTrash()).map((x) => x.record.kid)).toEqual(["trash-k1"]);

		// Dọn sạch Thùng rác vĩnh viễn
		const emptied = await manager.emptyTrash();
		expect(emptied).toBe(1);
		expect((await manager.listTrash()).length).toBe(0);

		await adapter.close();
	});

	test("2. CLI: remove -> trash list -> restore (khôi phục cả .pem) -> restore --from-bak", async () => {
		const jwksFile = join(tempDir, "jwks.json");
		const keysDir = join(tempDir, "keys");
		const cfgFile = join(tempDir, ".jwksctl.json");
		const baseFlags = ["--store", jwksFile, "--keys-dir", keysDir, "--config", cfgFile, "--json"];

		await runCli([...baseFlags, "init"]);
		const gen1 = JSON.parse(
			(await runCli([...baseFlags, "generate", "--alg", "EdDSA", "--kid", "pem-1"])).stdout,
		);
		await runCli([...baseFlags, "generate", "--alg", "ES256", "--kid", "pem-2"]);

		const pem1Path: string = gen1.record.privateKeyPath;
		expect(await Bun.file(pem1Path).exists()).toBe(true);

		// Xóa khóa pem-1 (chuyển vào Thùng rác)
		await runCli([...baseFlags, "remove", "pem-1", "--force", "--yes"]);
		expect(await Bun.file(pem1Path).exists()).toBe(false);

		// Kiểm tra danh sách trong Thùng rác qua lệnh `trash list`
		const trashRes = JSON.parse((await runCli([...baseFlags, "trash", "list"])).stdout);
		expect(trashRes.items.length).toBe(1);
		expect(trashRes.items[0].record.kid).toBe("pem-1");

		// Restore lại qua CLI `restore` -> cả bản ghi trong jwks.json lẫn file pem-1.pem đều quay trở lại
		const restoreRes = JSON.parse(
			(await runCli([...baseFlags, "restore", "pem-1", "--yes"])).stdout,
		);
		expect(restoreRes.restoredFromTrashCount).toBe(1);
		expect(restoreRes.restoredPemPaths).toEqual([pem1Path]);
		expect(await Bun.file(pem1Path).exists()).toBe(true);

		// Kiểm tra lệnh check báo toàn vẹn 100%
		const checkRes = JSON.parse((await runCli([...baseFlags, "check"])).stdout);
		expect(checkRes.valid).toBe(true);
		expect(checkRes.missingPrivateKeyFiles.length).toBe(0);

		// Test thêm trường hợp xóa khóa rồi chạy `restore --from-bak`
		const adapter = new JsonFileAdapter(jwksFile);
		const vault = new PemVault(keysDir);
		const manager = new KeyManagerService(adapter, vault);
		await manager.removeKeys(["pem-1"], { force: true });
		expect(await Bun.file(pem1Path).exists()).toBe(false);

		const bakRestore = await manager.restoreKeys({ fromBak: true });
		expect(bakRestore.mode).toBe("bak");
		expect(await Bun.file(pem1Path).exists()).toBe(true);
	});

	test("3. Mặc định jwks.json, keys/ và .trash/ luôn cố định tại thư mục cài đặt jwksctl dù đứng ở thư mục làm việc khác", async () => {
		const {
			DEFAULT_KEYS_DIR,
			DEFAULT_STORE_URI,
			DEFAULT_TRASH_DIR,
			INSTALL_DIR,
			resolveRuntimeContext,
		} = await import("../src/config/loader.ts");

		const origCwd = process.cwd();
		try {
			// Giả lập người dùng cd sang một thư mục dự án khác (tempDir)
			process.chdir(tempDir);

			const ctx = await resolveRuntimeContext({
				configPath: join(tempDir, "non-existent-config.json"),
			});
			const vault = new PemVault(ctx.profile.keysDir);

			expect(DEFAULT_STORE_URI).toBe(join(INSTALL_DIR, "jwks.json"));
			expect(DEFAULT_KEYS_DIR).toBe(join(INSTALL_DIR, "keys"));
			expect(DEFAULT_TRASH_DIR).toBe(join(INSTALL_DIR, ".trash"));
			expect(vault.trashDir).toBe(join(INSTALL_DIR, ".trash"));
		} finally {
			process.chdir(origCwd);
		}
	});

	test("4. Khi export ra file jwks.json đã tồn tại: Phát hiện file, lập Bảng Merge và cho phép chọn khóa Giữ / Bỏ", async () => {
		const storeFile = join(tempDir, "master-jwks.json");
		const keysDir = join(tempDir, "keys");
		const cfgFile = join(tempDir, ".jwksctl.json");
		const projectDir = join(tempDir, "my-app");
		const targetExportFile = join(projectDir, "jwks.json");
		const baseFlags = ["--store", storeFile, "--keys-dir", keysDir, "--config", cfgFile, "--json"];

		await runCli([...baseFlags, "init"]);
		// Tạo 2 khóa ban đầu và xuất ra file targetExportFile lần 1
		await runCli([...baseFlags, "generate", "--alg", "EdDSA", "--kid", "legacy-k1"]);
		await runCli([...baseFlags, "generate", "--alg", "ES256", "--kid", "shared-k2"]);

		const firstExport = JSON.parse(
			(await runCli([...baseFlags, "export", "-o", targetExportFile])).stdout,
		);
		expect(firstExport.targetFileExistsBefore).toBe(false);
		expect(firstExport.keptCount).toBe(2);

		// Xóa legacy-k1 khỏi Store và tạo thêm khóa mới new-k3 trong Store
		await runCli([...baseFlags, "remove", "legacy-k1", "--force", "--yes"]);
		await runCli([...baseFlags, "generate", "--alg", "RS256", "--kid", "new-k3"]);

		// Lúc này:
		// - File đích (targetExportFile) đang có: ["legacy-k1", "shared-k2"]
		// - Store đang có: ["shared-k2", "new-k3"]
		// Khi chạy export lần 2 kèm --drop legacy-k1:
		const secondExport = JSON.parse(
			(
				await runCli([
					...baseFlags,
					"export",
					"-o",
					targetExportFile,
					"--drop",
					"legacy-k1",
					"--yes",
				])
			).stdout,
		);

		expect(secondExport.targetFileExistsBefore).toBe(true);
		expect(
			secondExport.candidates.map((c: { kid: string; source: string }) => ({
				kid: c.kid,
				source: c.source,
			})),
		).toEqual([
			{ kid: "legacy-k1", source: "existing_only" },
			{ kid: "shared-k2", source: "both" },
			{ kid: "new-k3", source: "new_from_store" },
		]);
		expect(secondExport.keptCount).toBe(2);
		expect(secondExport.droppedCount).toBe(1);
		expect(secondExport.droppedKids).toEqual(["legacy-k1"]);

		const finalExportedJson = JSON.parse(await Bun.file(targetExportFile).text());
		expect(finalExportedJson.keys.map((k: { kid: string }) => k.kid)).toEqual([
			"shared-k2",
			"new-k3",
		]);
	});
});
