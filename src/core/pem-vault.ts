import { mkdir, rename, rm, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

const ENCRYPTED_HEADER = "-----BEGIN ENCRYPTED JWKSCTL PRIVATE KEY-----";
const ENCRYPTED_FOOTER = "-----END ENCRYPTED JWKSCTL PRIVATE KEY-----";
const PBKDF2_ITERATIONS = 100_000;

interface EncryptedPayload {
  v: 1;
  alg: "AES-256-GCM";
  kdf: "PBKDF2-SHA256";
  iter: number;
  salt: string;
  iv: string;
  ciphertext: string;
}

async function deriveAesKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptPemContent(pkcs8Pem: string, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(passphrase, salt);
  const encoded = new TextEncoder().encode(pkcs8Pem);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    key,
    encoded
  );

  const payload: EncryptedPayload = {
    v: 1,
    alg: "AES-256-GCM",
    kdf: "PBKDF2-SHA256",
    iter: PBKDF2_ITERATIONS,
    salt: Buffer.from(salt).toString("base64"),
    iv: Buffer.from(iv).toString("base64"),
    ciphertext: Buffer.from(cipherBuffer).toString("base64"),
  };

  const base64Body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
  const lines = base64Body.match(/.{1,64}/g) ?? [base64Body];
  return `${ENCRYPTED_HEADER}\n${lines.join("\n")}\n${ENCRYPTED_FOOTER}\n`;
}

export async function decryptPemContent(content: string, passphrase?: string): Promise<string> {
  const trimmed = content.trim();
  if (!trimmed.startsWith(ENCRYPTED_HEADER)) {
    return content;
  }
  if (!passphrase) {
    throw new Error(
      "File Private Key đang được mã hóa AES-256-GCM. Vui lòng cung cấp passphrase (--passphrase hoặc JWKS_PASSPHRASE)."
    );
  }

  const base64Body = trimmed
    .replace(ENCRYPTED_HEADER, "")
    .replace(ENCRYPTED_FOOTER, "")
    .replace(/\s+/g, "");

  let payload: EncryptedPayload;
  try {
    payload = JSON.parse(Buffer.from(base64Body, "base64").toString("utf8")) as EncryptedPayload;
  } catch {
    throw new Error("Định dạng file Private Key mã hóa không hợp lệ hoặc bị hỏng.");
  }

  const salt = new Uint8Array(Buffer.from(payload.salt, "base64"));
  const iv = new Uint8Array(Buffer.from(payload.iv, "base64"));
  const ciphertext = new Uint8Array(Buffer.from(payload.ciphertext, "base64"));
  const key = await deriveAesKey(passphrase, salt);

  try {
    const plainBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      key,
      new Uint8Array(ciphertext)
    );
    return new TextDecoder().decode(plainBuffer);
  } catch {
    throw new Error("Giải mã Private Key thất bại: Sai passphrase hoặc dữ liệu bị thay đổi.");
  }
}

export class PemVault {
  constructor(private readonly baseKeysDir: string = "./keys") {}

  getKeyFilePath(kid: string): string {
    const safeKid = kid.replace(/[^a-zA-Z0-9._-]/g, "_");
    return join(this.baseKeysDir, `${safeKid}.pem`);
  }

  async savePrivateKey(
    kid: string,
    pkcs8Pem: string,
    passphrase?: string
  ): Promise<{ privateKeyPath: string; isEncrypted: boolean }> {
    const filePath = this.getKeyFilePath(kid);
    const absPath = resolve(filePath);
    await mkdir(dirname(absPath), { recursive: true });

    const isEncrypted = Boolean(passphrase && passphrase.length > 0);
    const contentToWrite =
      passphrase && passphrase.length > 0
        ? await encryptPemContent(pkcs8Pem, passphrase)
        : pkcs8Pem.endsWith("\n")
          ? pkcs8Pem
          : `${pkcs8Pem}\n`;

    const tmpPath = `${absPath}.tmp.${process.pid}.${Date.now()}`;
    await Bun.write(tmpPath, contentToWrite);
    await rename(tmpPath, absPath);

    return {
      privateKeyPath: filePath.replace(/\\/g, "/"),
      isEncrypted,
    };
  }

  async loadPrivateKey(privateKeyPath: string, passphrase?: string): Promise<string> {
    const absPath = resolve(privateKeyPath);
    const file = Bun.file(absPath);
    if (!(await file.exists())) {
      throw new Error(`Không tìm thấy file Private Key tại đường dẫn: ${privateKeyPath}`);
    }
    const raw = await file.text();
    return decryptPemContent(raw, passphrase);
  }

  async exists(privateKeyPath: string): Promise<boolean> {
    try {
      const info = await stat(resolve(privateKeyPath));
      return info.isFile();
    } catch {
      return false;
    }
  }

  async deletePrivateKey(privateKeyPath: string): Promise<boolean> {
    const absPath = resolve(privateKeyPath);
    if (!(await this.exists(absPath))) {
      return false;
    }
    await rm(absPath, { force: true });
    return true;
  }
}
