export type LegacyFormat = 'secrets.js' | 'shamir' | 'sssa';
export const LEGACY_FORMATS: readonly LegacyFormat[];

export interface ParsedLegacyShare {
  format: LegacyFormat;
}

/** Recognises one legacy share; returns null if it is not one. Throws if it is one but malformed. */
export function parseLegacyShare(item: unknown): ParsedLegacyShare | null;

/** Combines parsed shares of one legacy format. The result is NOT verified. */
export function combineLegacyShares(shares: ParsedLegacyShare[]): Uint8Array;

/** Rewrites CESU-8 (as written by sssa-js) to UTF-8; UTF-8 passes through unchanged. */
export function cesu8ToUtf8(bytes: Uint8Array): Uint8Array;
