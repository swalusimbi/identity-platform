import { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";

export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public code?: string
  ) {
    super(message);
    this.name = "AppError";
  }

  static badRequest(message: string, code?: string) {
    return new AppError(400, message, code);
  }
  static unauthorized(message = "Unauthorized", code?: string) {
    return new AppError(401, message, code);
  }
  static forbidden(message = "Forbidden", code?: string) {
    return new AppError(403, message, code);
  }
  static notFound(message = "Not found", code?: string) {
    return new AppError(404, message, code);
  }
  static conflict(message: string, code?: string) {
    return new AppError(409, message, code);
  }
  static tooMany(message = "Too many requests", code?: string) {
    return new AppError(429, message, code);
  }
  static badGateway(message: string, code?: string) {
    return new AppError(502, message, code);
  }
}

export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
) {
  // Zod validation errors → 400 with field details
  if (err instanceof ZodError) {
    res.status(400).json({
      error: "Validation failed",
      code: "VALIDATION_ERROR",
      details: err.errors.map((e) => ({
        field: e.path.join("."),
        message: e.message,
      })),
    });
    return;
  }

  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      error: err.message,
      ...(err.code && { code: err.code }),
    });
    return;
  }

  // Unknown errors — log full trace, return generic message
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
}
