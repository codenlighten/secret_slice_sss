/**
 * Every failure this library reports is a SecretSlicesError with a stable
 * `code`. Nothing is ever reported by returning undefined or by a warning.
 */
export class SecretSlicesError extends Error {
  /**
   * @param {string} code stable machine-readable code, e.g. "ERR_INTEGRITY"
   * @param {string} message human-readable explanation
   * @param {object} [details] extra fields copied onto the error
   */
  constructor(code, message, details) {
    super(message);
    this.name = 'SecretSlicesError';
    this.code = code;
    if (details) Object.assign(this, details);
  }
}

export function fail(code, message, details) {
  throw new SecretSlicesError(code, message, details);
}
