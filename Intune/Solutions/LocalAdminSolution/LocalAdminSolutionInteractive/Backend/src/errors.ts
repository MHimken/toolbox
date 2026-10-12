export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
    public readonly headers?: Record<string, string>
  ) {
    super(message);
  }
}

export function isTableStatus(error: unknown, statusCode: number): boolean {
  return typeof error === 'object' && error !== null && 'statusCode' in error &&
    Number((error as { statusCode?: unknown }).statusCode) === statusCode;
}
