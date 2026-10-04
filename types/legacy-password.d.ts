/** True if `text` looks like a secret the 2024 SecretSlices app encrypted with a password. */
export function isPasswordEncrypted(text: unknown): boolean;

/**
 * Decrypts a secret the 2024 SecretSlices app encrypted with a password
 * (CryptoJS AES). Rejects with ERR_WRONG_PASSWORD if the password is wrong.
 */
export function decryptWithPassword(ciphertext: string, password: string): Promise<string>;
