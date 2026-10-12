import { resolve } from "node:path";
import type { JwksCtlConfig, StoreProfile, StoreType } from "../core/types.ts";
import type { IStorageAdapter } from "../storage/adapter.ts";
import { JsonFileAdapter } from "../storage/file-adapter.ts";
import { SqliteAdapter } from "../storage/sqlite-adapter.ts";

export const DEFAULT_CONFIG_FILE = ".jwksctl.json";

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

export async function loadConfigFile(
	configPath: string = DEFAULT_CONFIG_FILE,
): Promise<JwksCtlConfig | null> {
	const file = Bun.file(resolve(configPath));
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
	const absPath = resolve(configPath);
	await Bun.write(absPath, `${JSON.stringify(config, null, 2)}\n`);
}

export async function resolveRuntimeContext(opts: RuntimeOptions = {}): Promise<ResolvedContext> {
	const configFile = await loadConfigFile(opts.configPath);
	const envProfile = process.env.JWKS_PROFILE;
	const activeProfileName = opts.profile ?? envProfile ?? configFile?.defaultProfile ?? "default";

	const savedProfile: Partial<StoreProfile> = configFile?.profiles?.[activeProfileName] ?? {};

	const rawUri = opts.store ?? process.env.JWKS_STORE ?? savedProfile.uri ?? "./jwks.json";

	const type =
		savedProfile.type && !opts.store && !process.env.JWKS_STORE
			? savedProfile.type
			: detectStoreType(rawUri);

	const keysDir = opts.keysDir ?? process.env.JWKS_KEYS_DIR ?? savedProfile.keysDir ?? "./keys";

	const tableName =
		opts.tableName ?? process.env.JWKS_TABLE ?? savedProfile.tableName ?? "jwks_keys";

	const passphrase = opts.passphrase ?? process.env.JWKS_PASSPHRASE;

	return {
		profileName: activeProfileName,
		profile: {
			type,
			uri: rawUri,
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
		case "mysql":
		case "mongodb":
			throw new Error(
				`Adapter "${type}" sẽ được kích hoạt trong Giai đoạn 3. Hiện tại hỗ trợ ưu tiên "file" (jwks.json) và "sqlite".`,
			);
		default:
			throw new Error(`Loại Store không xác định: ${String(type)}`);
	}
}
