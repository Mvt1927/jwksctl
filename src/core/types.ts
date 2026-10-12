import type { JWK } from "jose";

export type KeyStatus = "active" | "passive" | "revoked";

export type SigningAlgorithm =
	"RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384" | "ES512" | "EdDSA";

export const SUPPORTED_ALGORITHMS: readonly SigningAlgorithm[] = [
	"RS256",
	"RS384",
	"RS512",
	"PS256",
	"PS384",
	"PS512",
	"ES256",
	"ES384",
	"ES512",
	"EdDSA",
] as const;

export const FORBIDDEN_PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/**
 * Public JWK chuẩn RFC 7517 (tuyệt đối không chứa thành phần khóa bí mật).
 */
export interface PublicJwk extends JWK {
	kty: "RSA" | "EC" | "OKP";
	kid: string;
	use: "sig";
	alg: SigningAlgorithm;
	d?: never;
	p?: never;
	q?: never;
	dp?: never;
	dq?: never;
	qi?: never;
	oth?: never;
	k?: never;
}

/**
 * Bản ghi JWK mở rộng lưu trong jwks.json hoặc Database.
 * Chỉ chứa Public JWK + metadata quản lý vòng đời + đường dẫn tới file Private Key (.pem).
 */
export interface JwkRecord extends PublicJwk {
	status: KeyStatus;
	privateKeyPath: string;
	isPrivateKeyEncrypted: boolean;
	createdAt: string;
	expiresAt: string | null;
	rotatedAt: string | null;
}

export interface JwksFilePayload {
	keys: JwkRecord[];
}

export interface PublicJwksPayload {
	keys: PublicJwk[];
}

export interface MutationDiff {
	beforeCount: number;
	afterCount: number;
	added: JwkRecord[];
	updated: Array<{ before: JwkRecord; after: JwkRecord }>;
	removed: JwkRecord[];
	unchangedCount: number;
	activeKeysRemoved: JwkRecord[];
}

export type StoreType = "file" | "sqlite" | "postgres" | "mysql" | "mongodb";

export interface StoreProfile {
	type: StoreType;
	/** Đường dẫn file (với file/sqlite) hoặc Connection URI (với postgres/mysql/mongodb) */
	uri: string;
	/** Thư mục lưu các file Private Key (.pem) */
	keysDir?: string;
	/** Tên bảng hoặc collection (mặc định: jwks_keys) */
	tableName?: string;
}

export interface JwksCtlConfig {
	defaultProfile: string;
	profiles: Record<string, StoreProfile>;
}
