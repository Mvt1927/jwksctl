import { existsSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import type { JwksCtlConfig, StoreProfile, StoreType } from "../core/types.ts";
import type { IStorageAdapter } from "../storage/adapter.ts";
import { JsonFileAdapter } from "../storage/file-adapter.ts";
import { MongoAdapter } from "../storage/mongo-adapter.ts";
import { SqlAdapter } from "../storage/sql-adapter.ts";
import { SqliteAdapter } from "../storage/sqlite-adapter.ts";

/**
 * Xác định thư mục cài đặt gốc của jwksctl (hoạt động cho cả `bun run index.ts` và file thực thi `dist/jwksctl.exe`).
 */
export function getInstallDir(): string {
	if (process.env.JWKSCTL_HOME) {
		return resolve(process.env.JWKSCTL_HOME);
	}

	const metaDir = import.meta.dir;
	const execName = basename(process.execPath).toLowerCase();
	const isCompiledBinary =
		metaDir.includes("~BUN") ||
		metaDir.includes("$bunfs") ||
		(execName !== "bun" &&
			execName !== "bun.exe" &&
			execName !== "node" &&
			execName !== "node.exe");

	if (isCompiledBinary) {
		const exeDir = dirname(resolve(process.execPath));
		if (
			basename(exeDir).toLowerCase() === "dist" &&
			existsSync(join(dirname(exeDir), "package.json"))
		) {
			return dirname(exeDir);
		}
		return exeDir;
	}

	return resolve(metaDir, "../..");
}

export const INSTALL_DIR = getInstallDir();
export const DEFAULT_CONFIG_FILE = join(INSTALL_DIR, ".jwksctl.json");
export const DEFAULT_STORE_URI = join(INSTALL_DIR, "jwks.json");
export const DEFAULT_KEYS_DIR = join(INSTALL_DIR, "keys");
export const DEFAULT_TRASH_DIR = join(INSTALL_DIR, ".trash");

export interface RuntimeOptions {
	store?: string;
	profile?: string;
	keysDir?: string;
	tableName?: string;
	passphrase?: string;
	configPath?: string;
}

export interface ResolvedContext {
	profileName: string;
	profile: Required<StoreProfile>;
	passphrase?: string;
}

export function detectStoreType(uri: string): StoreType {
	const lower = uri.trim().toLowerCase();
	if (lower.startsWith("postgres://") || lower.startsWith("postgresql://")) {
		return "postgres";
	}
	if (lower.startsWith("mysql://") || lower.startsWith("mariadb://")) {
		return "mysql";
	}
	if (lower.startsWith("mongodb://") || lower.startsWith("mongodb+srv://")) {
		return "mongodb";
	}
	if (
		lower.startsWith("sqlite://") ||
		lower === ":memory:" ||
		lower.endsWith(".sqlite") ||
		lower.endsWith(".sqlite3") ||
		lower.endsWith(".db")
	) {
		return "sqlite";
	}
	return "file";
}

function resolveInstallRelativePath(p: string, baseDir: string = INSTALL_DIR): string {
	if (isAbsolute(p)) {
		return resolve(p);
	}
	return resolve(baseDir, p);
}

export async function loadConfigFile(
	configPath: string = DEFAULT_CONFIG_FILE,
): Promise<JwksCtlConfig | null> {
	const absConfigPath = isAbsolute(configPath) ? configPath : resolve(INSTALL_DIR, configPath);
	const file = Bun.file(absConfigPath);
	if (!(await file.exists())) {
		return null;
	}
	const raw = await file.text();
	return JSON.parse(raw) as JwksCtlConfig;
}

export async function saveConfigFile(
	config: JwksCtlConfig,
	configPath: string = DEFAULT_CONFIG_FILE,
): Promise<void> {
	const absPath = isAbsolute(configPath) ? configPath : resolve(INSTALL_DIR, configPath);
	await Bun.write(absPath, `${JSON.stringify(config, null, 2)}\n`);
}

export async function resolveRuntimeContext(opts: RuntimeOptions = {}): Promise<ResolvedContext> {
	const effectiveConfigPath = opts.configPath ?? DEFAULT_CONFIG_FILE;
	const configBaseDir = dirname(
		isAbsolute(effectiveConfigPath)
			? effectiveConfigPath
			: resolve(INSTALL_DIR, effectiveConfigPath),
	);
	const configFile = await loadConfigFile(effectiveConfigPath);
	const envProfile = process.env.JWKS_PROFILE;
	const activeProfileName = opts.profile ?? envProfile ?? configFile?.defaultProfile ?? "default";

	const savedProfile: Partial<StoreProfile> = configFile?.profiles?.[activeProfileName] ?? {};

	const explicitStore = opts.store ?? process.env.JWKS_STORE;
	const rawUri = explicitStore ?? savedProfile.uri ?? DEFAULT_STORE_URI;

	const type = savedProfile.type && !explicitStore ? savedProfile.type : detectStoreType(rawUri);

	// Nếu dùng file/sqlite từ profile hoặc mặc định (không truyền --store trực tiếp), luôn neo theo thư mục cài đặt jwksctl
	let resolvedUri = rawUri;
	if (
		(type === "file" ||
			(type === "sqlite" && rawUri !== ":memory:" && !rawUri.startsWith("sqlite://"))) &&
		!explicitStore
	) {
		resolvedUri = resolveInstallRelativePath(rawUri, configBaseDir);
	} else if (type === "file" && explicitStore) {
		resolvedUri = resolve(explicitStore);
	}

	const explicitKeysDir = opts.keysDir ?? process.env.JWKS_KEYS_DIR;
	const rawKeysDir = explicitKeysDir ?? savedProfile.keysDir ?? DEFAULT_KEYS_DIR;
	const keysDir = explicitKeysDir
		? resolve(explicitKeysDir)
		: resolveInstallRelativePath(rawKeysDir, configBaseDir);

	const tableName =
		opts.tableName ?? process.env.JWKS_TABLE ?? savedProfile.tableName ?? "jwks_keys";

	const passphrase = opts.passphrase ?? process.env.JWKS_PASSPHRASE;

	return {
		profileName: activeProfileName,
		profile: {
			type,
			uri: resolvedUri,
			keysDir,
			tableName,
		},
		passphrase,
	};
}

export function createStorageAdapter(profile: StoreProfile): IStorageAdapter {
	const type = profile.type ?? detectStoreType(profile.uri);
	const tableName = profile.tableName ?? "jwks_keys";

	switch (type) {
		case "file":
			return new JsonFileAdapter(profile.uri);
		case "sqlite":
			return new SqliteAdapter(profile.uri, tableName);
		case "postgres":
			return new SqlAdapter(profile.uri, "postgres", tableName);
		case "mysql":
			return new SqlAdapter(profile.uri, "mysql", tableName);
		case "mongodb":
			return new MongoAdapter(profile.uri, tableName);
		default:
			throw new Error(`Loại Store không xác định: ${String(type)}`);
	}
}
