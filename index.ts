#!/usr/bin/env bun
import pc from "picocolors";
import { runInteractiveWizard } from "./src/cli/interactive.ts";
import { buildCliProgram } from "./src/cli/program.ts";
import { createStorageAdapter, resolveRuntimeContext } from "./src/config/loader.ts";
import { KeyManagerService } from "./src/core/key-manager.ts";
import { PemVault } from "./src/core/pem-vault.ts";

async function main(): Promise<void> {
	const args = process.argv.slice(2);

	// Nếu người dùng gõ `jwksctl` không kèm đối số trên terminal tương tác -> tự bật Interactive Wizard
	if (args.length === 0 && process.stdin.isTTY) {
		const ctx = await resolveRuntimeContext();
		const adapter = createStorageAdapter(ctx.profile);
		const vault = new PemVault(ctx.profile.keysDir);
		const manager = new KeyManagerService(adapter, vault);
		try {
			await runInteractiveWizard(manager, ctx.passphrase);
		} finally {
			await adapter.close?.();
		}
		return;
	}

	const program = buildCliProgram();
	await program.parseAsync(process.argv);
}

main().catch((err: unknown) => {
	const message = err instanceof Error ? err.message : String(err);
	console.error(`${pc.red(pc.bold("✗ Lỗi:"))} ${message}`);
	process.exit(1);
});
