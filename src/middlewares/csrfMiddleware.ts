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
    httpOnly: false, // ❗ Debe ser false para que JS pueda leerlo
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000, // 24 horas
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

  // Validar que existan ambos tokens
  if (!csrfTokenFromCookie || !csrfTokenFromHeader) {
    res.status(403).json({
      success: false,
      error: "Token CSRF no proporcionado",
    });
    return;
  }

  // Validar que coincidan
  if (csrfTokenFromCookie !== csrfTokenFromHeader) {
    res.status(403).json({
      success: false,
      error: "Token CSRF inválido",
    });
    return;
  }

  // Token válido, continuar
  next();
};
