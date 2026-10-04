export type ErrorCode =
  | 'ERR_INVALID_ARGUMENT'
  | 'ERR_INVALID_SHARE'
  | 'ERR_SHARE_CHECKSUM'
  | 'ERR_UNSUPPORTED_VERSION'
  | 'ERR_MIXED_SHARES'
  | 'ERR_DUPLICATE_SHARE'
  | 'ERR_INSUFFICIENT_SHARES'
  | 'ERR_INTEGRITY'
  | 'ERR_INVALID_UTF8'
  | 'ERR_WRONG_PASSWORD'
  | 'ERR_NO_RANDOM';

/** The only error type this library throws for bad input or failed recovery. */
export class SecretSlicesError extends Error {
  readonly name: 'SecretSlicesError';
  readonly code: ErrorCode;
  /** Zero-based position, in the input, of the share at fault (when one share is). */
  readonly shareIndex?: number;
  /** With ERR_INSUFFICIENT_SHARES: how many different shares are needed. */
  readonly required?: number;
  /** With ERR_INSUFFICIENT_SHARES: how many different shares were given. */
  readonly provided?: number;
  constructor(code: ErrorCode, message: string, details?: object);
}

export type Format = 'ss1' | 'secrets.js' | 'shamir' | 'sssa';

/** Every share format this version can read. New shares are always "ss1". */
export const FORMATS: readonly Format[];

export interface SplitOptions {
  /** Total number of shares to create, 2 to 255. */
  shares: number;
  /** Number of shares needed to recover the secret, 2 to `shares`. */
  threshold: number;
  /**
   * Pad the secret so its length (plus one marker byte) is a multiple of this
   * many bytes, hiding its exact length. 1 to 65536; default 1 (no padding).
   */
  padTo?: number;
}

/**
 * Splits a secret into shares. Any `threshold` of them recover it; fewer
 * reveal nothing about it except an upper bound on its length.
 * A string is stored as UTF-8.
 */
export function split(secret: string | Uint8Array, options: SplitOptions): string[];

/** Recovers and verifies a secret from ss1 shares, given in any order. */
export function combine(shares: Iterable<string>): Uint8Array;

/** Like combine(), for a secret that was given to split() as a string. */
export function combineText(shares: Iterable<string>): string;

export interface LegacyShareObject {
  part?: number | string;
  value: string;
}

export interface Recovered {
  secret: Uint8Array;
  format: Format;
  /** True only for ss1, the one format that can prove the result is the original secret. */
  verified: boolean;
  /** The secret as text. Throws ERR_INVALID_UTF8 if it is not valid text. */
  text(): string;
}

/**
 * Recovers a secret from shares in any format SecretSlices has ever produced:
 * an array of strings or {part, value} objects, pasted text with one share
 * per line, or the JSON written by the older apps.
 */
export function recover(input: string | Iterable<string | LegacyShareObject | { share: string }>): Recovered;

export interface ShareInfo {
  format: 'ss1';
  threshold: number;
  /** This share's number, 1 to 255. */
  index: number;
  /** 16 hex digits, the same for all shares of one split. */
  setId: string;
  /** The secret is at most this many bytes (exactly this many unless padTo was used). */
  maxSecretBytes: number;
}

/** Describes one ss1 share. Throws if it is damaged or not an ss1 share. */
export function inspect(share: string): ShareInfo;

export type Validation =
  | { valid: true; format: Format; threshold?: number; index?: number; setId?: string }
  | { valid: false; code: ErrorCode; message: string };

/** Checks one share in any supported format. Never throws. */
export function validate(share: unknown): Validation;
