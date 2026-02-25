/**
 * Librgrn Central Error Library
 * Node.js + TypeScript strict mode
 * Fully modular, extendable, standard-library style
 */
export type ErrorCode =
  | "AUTH_INVALID"
  | "AUTH_EXPIRED"
  | "TOKEN_INVALID"
  | "TOKEN_EXPIRED"
  | "CRYPTO_FAIL"
  | "VALIDATION_ERROR"
  | "PIN_INVALID"
  | "PASSWORD_WEAK"
  | "UNKNOWN_ERROR";
export interface BaseErrorOptions {
  message?: string;
  code?: ErrorCode;
  meta?: Record<string, unknown> | undefined;
  cause?: Error | undefined;
}
export class LibrgrnError extends Error {
  public readonly code: ErrorCode;
  public readonly meta: Record<string, unknown> | undefined;
  public readonly cause: Error | undefined;
  constructor(options: BaseErrorOptions) {
    super(options.message ?? "An unknown error occurred");
    Object.setPrototypeOf(this, new.target.prototype);
    this.name = this.constructor.name;
    this.code = options.code ?? "UNKNOWN_ERROR";
    this.meta = options.meta;
    this.cause = options.cause;
    if ((Error as any).captureStackTrace) {
      (Error as any).captureStackTrace(this, this.constructor);
    }
  }
  public toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      meta: this.meta,
      cause: this.cause
        ? { name: this.cause.name, message: this.cause.message }
        : undefined,
      stack: this.stack,
    };
  }
}
export class AuthError extends LibrgrnError {
  constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
    super({
      message: message ?? "Authentication failed",
      code: "AUTH_INVALID",
      meta,
      cause,
    });
  }
}
export class TokenError extends LibrgrnError {
  constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
    super({
      message: message ?? "Token error",
      code: "TOKEN_INVALID",
      meta,
      cause,
    });
  }
}
export class CryptoError extends LibrgrnError {
  constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
    super({
      message: message ?? "Cryptography operation failed",
      code: "CRYPTO_FAIL",
      meta,
      cause,
    });
  }
}
export class ValidationError extends LibrgrnError {
  constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
    super({
      message: message ?? "Validation failed",
      code: "VALIDATION_ERROR",
      meta,
      cause,
    });
  }
}
export class PinError extends LibrgrnError {
  constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
    super({
      message: message ?? "PIN is invalid",
      code: "PIN_INVALID",
      meta,
      cause,
    });
  }
}
export class PasswordError extends LibrgrnError {
  constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
    super({
      message: message ?? "Password is weak",
      code: "PASSWORD_WEAK",
      meta,
      cause,
    });
  }
}
export const throwError = (error: LibrgrnError): never => {
  console.error(JSON.stringify(error.toJSON(), null, 2));
  throw error;
};
export const wrapError = (fn: () => void, fallback: BaseErrorOptions): void => {
  try {
    fn();
  } catch (err) {
    throw new LibrgrnError({
      ...fallback,
      cause: err instanceof Error ? err : undefined,
    });
  }
};
