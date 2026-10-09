/** The aggregator refused the certification request with a status the SDK knows. */
export class StampError extends Error {
  public constructor(public readonly status: string) {
    super(`Aggregator rejected the certification request: ${status}`);
    this.name = 'StampError';
  }
}

/**
 * @param {unknown} error Thrown value.
 * @returns {string} The message of an Error, or the string form of anything else.
 */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
