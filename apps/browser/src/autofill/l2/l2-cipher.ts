import { CipherType } from "@bitwarden/common/vault/enums";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";

/**
 * Any `l2:` value, including unknown versions, must never be filled as-is (PROTOCOL.md §2).
 * Kept free of the protocol import so cheap checks don't pull libsodium into every bundle.
 */
export function isL2Value(value: string | null | undefined): boolean {
  return value != null && value.startsWith("l2:");
}

/** True when a login's password or TOTP is L2 ciphertext. */
export function isL2Cipher(cipher: CipherView | null | undefined): boolean {
  return (
    cipher?.type === CipherType.Login &&
    (isL2Value(cipher.login?.password) || isL2Value(cipher.login?.totp))
  );
}
