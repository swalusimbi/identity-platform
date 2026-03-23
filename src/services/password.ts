import * as argon2 from "argon2";

// Tuned for a small VPS (4 vCPU, 8GB RAM)
// memoryCost: 64MB, timeCost: 3, parallelism: 2
// This takes ~200ms per hash — fast enough for login, brutal for attackers
const HASH_OPTIONS: argon2.Options = {
  type: argon2.argon2id, // Hybrid — resists both GPU and side-channel attacks
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 2,
};

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, HASH_OPTIONS);
}

export async function verifyPassword(
  hash: string,
  password: string
): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}
