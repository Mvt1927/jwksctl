import {
	calculateJwkThumbprint,
	exportJWK,
	exportPKCS8,
	exportSPKI,
	generateKeyPair,
	importJWK,
	importPKCS8,
	jwtVerify,
	SignJWT,
	type JWK,
	type JWTPayload,
} from "jose";
import {
	FORBIDDEN_PRIVATE_JWK_FIELDS,
	SUPPORTED_ALGORITHMS,
	type JwkRecord,
	type PublicJwk,
	type SigningAlgorithm,
} from "./types.ts";

const INTERNAL_METADATA_FIELDS = [
	"status",
	"privateKeyPath",
	"isPrivateKeyEncrypted",
	"createdAt",
	"expiresAt",
	"rotatedAt",
] as const;

export function isValidAlgorithm(alg: string): alg is SigningAlgorithm {
	return (SUPPORTED_ALGORITHMS as readonly string[]).includes(alg);
}

/**
 * Loại bỏ hoàn toàn mọi thành phần khóa bí mật và metadata nội bộ để trả về Public JWK chuẩn RFC 7517.
 */
export function sanitizePublicJwk(
	rawJwk: JWK,
	overrides: { kid: string; alg: SigningAlgorithm; use?: "sig" },
): PublicJwk {
	const copy: Record<string, unknown> = { ...rawJwk };
	for (const field of FORBIDDEN_PRIVATE_JWK_FIELDS) {
		delete copy[field];
	}
	for (const metaField of INTERNAL_METADATA_FIELDS) {
		delete copy[metaField];
	}

	if (copy.kty !== "RSA" && copy.kty !== "EC" && copy.kty !== "OKP") {
		throw new Error(`Loại khóa (kty) không được hỗ trợ: ${String(copy.kty)}`);
	}

	return {
		...(copy as unknown as PublicJwk),
		kty: copy.kty,
		kid: overrides.kid,
		alg: overrides.alg,
		use: overrides.use ?? "sig",
	};
}

/**
 * Chuyển đổi JwkRecord nội bộ sang PublicJwk thuần RFC 7517 (dùng cho export và /.well-known/jwks.json).
 */
export function toCleanPublicJwk(record: JwkRecord): PublicJwk {
	return sanitizePublicJwk(record, {
		kid: record.kid,
		alg: record.alg,
		use: record.use,
	});
}

export interface GenerateKeyMaterialOptions {
	alg: SigningAlgorithm;
	kid?: string;
	modulusLength?: number;
}

export interface GeneratedKeyMaterial {
	kid: string;
	alg: SigningAlgorithm;
	publicJwk: PublicJwk;
	privateKeyPem: string;
}

export async function generateKeyMaterial(
	options: GenerateKeyMaterialOptions,
): Promise<GeneratedKeyMaterial> {
	if (!isValidAlgorithm(options.alg)) {
		throw new Error(
			`Thuật toán "${options.alg}" không hợp lệ. Hỗ trợ: ${SUPPORTED_ALGORITHMS.join(", ")}`,
		);
	}

	const modulusLength = options.modulusLength ?? 2048;
	const { publicKey, privateKey } = await generateKeyPair(options.alg, {
		extractable: true,
		modulusLength,
	});

	const rawPublicJwk = await exportJWK(publicKey);
	const privateKeyPem = await exportPKCS8(privateKey);

	const thumbprint = await calculateJwkThumbprint(rawPublicJwk, "sha256");
	const datePrefix = new Date().toISOString().slice(0, 7); // YYYY-MM
	const resolvedKid = options.kid?.trim() || `${datePrefix}-${thumbprint.slice(0, 12)}`;

	const publicJwk = sanitizePublicJwk(rawPublicJwk, {
		kid: resolvedKid,
		alg: options.alg,
		use: "sig",
	});

	return {
		kid: resolvedKid,
		alg: options.alg,
		publicJwk,
		privateKeyPem,
	};
}

/**
 * Nhập khóa từ chuỗi PKCS#8 Private Key PEM và trích xuất ra Public JWK + PKCS#8 PEM chuẩn.
 */
export async function extractPublicJwkFromPrivatePem(
	pkcs8Pem: string,
	alg: SigningAlgorithm,
	customKid?: string,
): Promise<GeneratedKeyMaterial> {
	const privateCryptoKey = await importPKCS8(pkcs8Pem, alg, { extractable: true });
	const exportedJwk = await exportJWK(privateCryptoKey);
	const normalizedPrivatePem = await exportPKCS8(privateCryptoKey);

	const thumbprint = await calculateJwkThumbprint(exportedJwk, "sha256");
	const datePrefix = new Date().toISOString().slice(0, 7);
	const resolvedKid = customKid?.trim() || `${datePrefix}-${thumbprint.slice(0, 12)}`;

	const publicJwk = sanitizePublicJwk(exportedJwk, {
		kid: resolvedKid,
		alg,
		use: "sig",
	});

	return {
		kid: resolvedKid,
		alg,
		publicJwk,
		privateKeyPem: normalizedPrivatePem,
	};
}

/**
 * Nhập từ một đối tượng JWK (có chứa thành phần private `d`) và tách riêng Public JWK + PKCS#8 PEM.
 */
export async function extractFromJwkObject(
	jwkInput: JWK,
	fallbackAlg?: SigningAlgorithm,
	customKid?: string,
): Promise<GeneratedKeyMaterial> {
	const algCandidate = (jwkInput.alg ?? fallbackAlg) as string | undefined;
	if (!algCandidate || !isValidAlgorithm(algCandidate)) {
		throw new Error(
			`JWK đầu vào thiếu trường "alg" hợp lệ. Vui lòng chỉ định --alg (${SUPPORTED_ALGORITHMS.join(", ")}).`,
		);
	}
	if (!("d" in jwkInput) || !jwkInput.d) {
		throw new Error(
			"JWK nhập vào phải chứa thành phần Private Key ('d') để lưu file .pem và trích xuất Public JWK.",
		);
	}

	const importedKey = await importJWK(jwkInput, algCandidate, { extractable: true });
	if (!(importedKey instanceof CryptoKey)) {
		throw new Error("Chỉ hỗ trợ khóa bất đối xứng (RSA, EC, OKP).");
	}

	const privateKeyPem = await exportPKCS8(importedKey);
	const thumbprint = await calculateJwkThumbprint(jwkInput, "sha256");
	const datePrefix = new Date().toISOString().slice(0, 7);
	const resolvedKid =
		customKid?.trim() || jwkInput.kid?.trim() || `${datePrefix}-${thumbprint.slice(0, 12)}`;

	const publicJwk = sanitizePublicJwk(jwkInput, {
		kid: resolvedKid,
		alg: algCandidate,
		use: "sig",
	});

	return {
		kid: resolvedKid,
		alg: algCandidate,
		publicJwk,
		privateKeyPem,
	};
}

export async function exportPublicJwkToPem(publicJwk: PublicJwk): Promise<string> {
	const key = await importJWK(toCleanPublicJwk(publicJwk as JwkRecord), publicJwk.alg, {
		extractable: true,
	});
	if (!(key instanceof CryptoKey)) {
		throw new Error("Không thể chuyển đổi khóa sang SPKI PEM.");
	}
	return exportSPKI(key);
}

export async function signJwtWithPem(options: {
	privateKeyPem: string;
	alg: SigningAlgorithm;
	kid: string;
	payload: JWTPayload;
	expiresIn?: string;
	issuer?: string;
	audience?: string;
	subject?: string;
}): Promise<string> {
	const privateKey = await importPKCS8(options.privateKeyPem, options.alg);
	const signer = new SignJWT(options.payload)
		.setProtectedHeader({ alg: options.alg, kid: options.kid, typ: "JWT" })
		.setIssuedAt();

	if (options.expiresIn) signer.setExpirationTime(options.expiresIn);
	if (options.issuer) signer.setIssuer(options.issuer);
	if (options.audience) signer.setAudience(options.audience);
	if (options.subject) signer.setSubject(options.subject);

	return signer.sign(privateKey);
}

export async function verifyJwtWithPublicJwk(
	token: string,
	publicJwk: PublicJwk,
): Promise<{ payload: JWTPayload; protectedHeader: Record<string, unknown> }> {
	const cleanJwk = sanitizePublicJwk(publicJwk, {
		kid: publicJwk.kid,
		alg: publicJwk.alg,
		use: "sig",
	});
	const cryptoKey = await importJWK(cleanJwk, publicJwk.alg);
	const result = await jwtVerify(token, cryptoKey, {
		algorithms: [publicJwk.alg],
	});
	return {
		payload: result.payload,
		protectedHeader: result.protectedHeader as Record<string, unknown>,
	};
}
