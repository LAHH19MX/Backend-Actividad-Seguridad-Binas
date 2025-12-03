import { Response, NextFunction } from "express";
import { AuthRequest } from "../types";
import crypto from "crypto";

/**
 * Genera un token CSRF único
 */
export const generateCSRFToken = (): string => {
  return crypto.randomBytes(32).toString("hex");
};

/**
 * Middleware para generar y enviar token CSRF
 * Se ejecuta en rutas que necesitan protección CSRF (login, etc.)
 */
export const setCSRFToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  // Generar token CSRF
  const csrfToken = generateCSRFToken();

  // Guardarlo en cookie separada
  res.cookie("csrf_token", csrfToken, {
    httpOnly: false,
    secure: true,
    sameSite: "none",
    maxAge: 15 * 60 * 1000,
    path: "/",
  });

  next();
};

/**
 * Middleware para validar token CSRF en peticiones POST/PUT/DELETE
 */
export const validateCSRFToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  // Solo validar en métodos que modifican datos
  if (!["POST", "PUT", "DELETE", "PATCH"].includes(req.method)) {
    next();
    return;
  }

  // Obtener tokens
  const csrfTokenFromCookie = req.cookies.csrf_token;
  const csrfTokenFromHeader = req.headers["x-csrf-token"];

  // 🔍 Convertir header a string si es array
  const headerValue = Array.isArray(csrfTokenFromHeader)
    ? csrfTokenFromHeader[0]
    : csrfTokenFromHeader;

  // 🔍 DEBUG TEMPORAL
  console.log("🔍 CSRF Validation Debug:", {
    method: req.method,
    url: req.url,
    hasCookie: !!csrfTokenFromCookie,
    hasHeader: !!headerValue,
    cookieValue: csrfTokenFromCookie
      ? csrfTokenFromCookie.substring(0, 10) + "..."
      : "MISSING",
    headerValue: headerValue ? headerValue.substring(0, 10) + "..." : "MISSING",
    match: csrfTokenFromCookie === headerValue,
  });

  // Validar que existan ambos tokens
  if (!csrfTokenFromCookie || !headerValue) {
    console.error("❌ CSRF token faltante:", {
      cookie: !!csrfTokenFromCookie,
      header: !!headerValue,
    });
    res.status(403).json({
      success: false,
      error: "Token CSRF no proporcionado",
    });
    return;
  }

  // Validar que coincidan
  if (csrfTokenFromCookie !== headerValue) {
    console.error("❌ CSRF tokens no coinciden");
    res.status(403).json({
      success: false,
      error: "Token CSRF inválido",
    });
    return;
  }

  console.log("✅ CSRF token válido");
  next();
};
