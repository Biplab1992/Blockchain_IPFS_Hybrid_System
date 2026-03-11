import crypto from "crypto";
import os from "os";
import type { Request, RequestHandler } from "express";

export type LogLevel = "info" | "warn" | "error";

export function logEvent(level: LogLevel, message: string, fields?: Record<string, unknown>): void {
  const payload = {
    ts: new Date().toISOString(),
    level,
    message,
    ...(fields || {}),
  };
  const line = JSON.stringify(payload);
  if (level === "error") {
    console.error(line);
    return;
  }
  if (level === "warn") {
    console.warn(line);
    return;
  }
  console.log(line);
}

export function getRequestId(req: Request): string {
  const existing = String((req as any).requestId || "").trim();
  return existing || "unknown";
}

export function isLocalDevOrigin(origin: string): boolean {
  try {
    const parsed = new URL(origin);
    if (!["http:", "https:"].includes(parsed.protocol)) return false;
    if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1") {
      return true;
    }

    const isPrivateIpv4 =
      /^10\./.test(parsed.hostname) ||
      /^192\.168\./.test(parsed.hostname) ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(parsed.hostname);
    return isPrivateIpv4;
  } catch {
    return false;
  }
}

export function getPreferredLanIpv4(): string | null {
  const nets = os.networkInterfaces();
  for (const entries of Object.values(nets)) {
    for (const net of entries || []) {
      if (net.family !== "IPv4" || net.internal) continue;
      if (/^10\./.test(net.address) || /^192\.168\./.test(net.address) || /^172\.(1[6-9]|2\d|3[0-1])\./.test(net.address)) {
        return net.address;
      }
    }
  }
  return null;
}

export function createRequestLoggingMiddleware(): RequestHandler {
  return (req, res, next) => {
    const inboundRequestId = String(req.header("x-request-id") || "").trim();
    const requestId = inboundRequestId || crypto.randomUUID();
    const startedAtMs = Date.now();
    (req as any).requestId = requestId;
    res.setHeader("x-request-id", requestId);

    logEvent("info", "http_request_start", {
      requestId,
      method: req.method,
      path: req.originalUrl || req.url,
      ip: req.ip,
    });

    res.on("finish", () => {
      logEvent("info", "http_request_finish", {
        requestId,
        method: req.method,
        path: req.originalUrl || req.url,
        statusCode: res.statusCode,
        durationMs: Date.now() - startedAtMs,
      });
    });
    next();
  };
}
