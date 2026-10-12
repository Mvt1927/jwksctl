import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCliProgram } from "../src/cli/program.ts";

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

describe("Phase 2: CLI Subcommands End-to-End", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "jwksctl-cli-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("1. Luồng CLI đầy đủ: init -> generate -> sign -> verify -> rotate -> remove đa khóa -> restore -> check -> export", async () => {
    const jwksFile = join(tempDir, "jwks.json");
    const keysDir = join(tempDir, "keys");
    const cfgFile = join(tempDir, ".jwksctl.json");
    const baseFlags = [
      "--store",
      jwksFile,
      "--keys-dir",
      keysDir,
      "--config",
      cfgFile,
      "--json",
    ];

    // 1. Init kèm lưu profile
    const initRes = JSON.parse(
      (await runCli([...baseFlags, "init", "--save-profile", "local-json"])).stdout
    );
    expect(initRes.initialized).toBe(true);
    expect(initRes.profile).toBe("local-json");

    // 2. Tạo 2 khóa passive và 1 khóa active
    await runCli([
      ...baseFlags,
      "generate",
      "--alg",
      "EdDSA",
      "--kid",
      "cli-k1",
      "--status",
      "passive",
    ]);
    await runCli([
      ...baseFlags,
      "generate",
      "--alg",
      "ES256",
      "--kid",
      "cli-k2",
      "--status",
      "passive",
    ]);
    await runCli([
      ...baseFlags,
      "generate",
      "--alg",
      "EdDSA",
      "--kid",
      "cli-k3",
      "--status",
      "active",
    ]);

    // 3. Ký và xác thực JWT qua CLI
    const signRes = JSON.parse(
      (
        await runCli([
          ...baseFlags,
          "sign",
          "--data",
          '{"sub":"cli-user","scope":"read:keys"}',
          "--iss",
          "jwksctl-auth",
        ])
      ).stdout
    );
    expect(signRes.kid).toBe("cli-k3");
    expect(typeof signRes.token).toBe("string");

    const verifyRes = JSON.parse(
      (await runCli([...baseFlags, "verify", signRes.token])).stdout
    );
    expect(verifyRes.payload.sub).toBe("cli-user");
    expect(verifyRes.matchedKey.kid).toBe("cli-k3");

    // 4. Rotate sang khóa mới cli-k4 (cli-k3 chuyển sang passive)
    const rotateRes = JSON.parse(
      (
        await runCli([
          ...baseFlags,
          "rotate",
          "--alg",
          "ES256",
          "--kid",
          "cli-k4",
          "--grace-period",
          "24h",
        ])
      ).stdout
    );
    expect(rotateRes.newRecord.kid).toBe("cli-k4");
    expect(rotateRes.demotedKids).toEqual(["cli-k3"]);

    // 5. Xóa cùng lúc 2 khóa ("cli-k1" và "cli-k2") qua CLI lệnh remove
    const removeRes = JSON.parse(
      (await runCli([...baseFlags, "remove", "cli-k1,cli-k2", "--yes"])).stdout
    );
    expect(removeRes.diff.beforeCount).toBe(4);
    expect(removeRes.diff.afterCount).toBe(2);

    const listAfterRemove = JSON.parse((await runCli([...baseFlags, "list"])).stdout);
    expect(listAfterRemove.keys.map((k: { kid: string }) => k.kid)).toEqual([
      "cli-k3",
      "cli-k4",
    ]);

    // 6. Khôi phục từ bản sao lưu .bak qua lệnh restore
    const restoreRes = JSON.parse((await runCli([...baseFlags, "restore"])).stdout);
    expect(restoreRes.restoredCount).toBe(4);

    // 7. Kiểm tra toàn vẹn qua lệnh check
    const checkRes = JSON.parse((await runCli([...baseFlags, "check"])).stdout);
    expect(checkRes.valid).toBe(true);
    expect(checkRes.totalKeys).toBe(4);
    expect(checkRes.missingPrivateKeyFiles.length).toBe(0);

    // 8. Xuất Public JWKS ra file và đồng bộ sang SQLite
    const exportedFile = join(tempDir, "public-jwks.json");
    await runCli([...baseFlags, "export", "--output", exportedFile]);
    const exportedContent = JSON.parse(await Bun.file(exportedFile).text());
    expect(exportedContent.keys.length).toBe(4);
    expect(exportedContent.keys[0].privateKeyPath).toBeUndefined();

    const sqliteTarget = join(tempDir, "synced.sqlite");
    const syncRes = JSON.parse(
      (await runCli([...baseFlags, "sync", "--to", sqliteTarget])).stdout
    );
    expect(syncRes.addedCount).toBe(4);
  });
});
