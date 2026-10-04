export type WordCount = 12 | 15 | 18 | 21 | 24;

/** A new random BIP-39 English phrase. Default: 12 words. */
export function generateMnemonic(words?: WordCount): string;

/** The BIP-39 phrase for 16, 20, 24, 28 or 32 bytes of entropy. */
export function entropyToMnemonic(entropy: Uint8Array): string;

/** True if the phrase is a BIP-39 English mnemonic with a correct checksum. */
export function validateMnemonic(phrase: string): boolean;
