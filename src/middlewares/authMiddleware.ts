import { Response, NextFunction } from "express";
import { verifyToken } from "../utils/jwt";
import { isSessionValid } from "../utils/sessionHelper";
import { AuthRequest } from "../types";

/**
 * Middleware de autenticación JWT con cookies
 * Verifica que el usuario esté autenticado Y que la sesión sea válida en BD
 */
export const authenticate = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // 1. Obtener token de las cookies
    const token = req.cookies.auth_token;

    if (!token) {
      res.status(401).json({
        success: false,
        error: "No se proporcionó token de autenticación",
      });
      return;
    }

    // 2. Verificar y decodificar token JWT
    const decoded = verifyToken(token);

    if (!decoded) {
      res.status(401).json({
        success: false,
        error: "Token inválido o expirado",
      });
      return;
    }

    // 3. Verificar que la sesión exista en BD
    const sessionValid = await isSessionValid(decoded.jti, token);

    if (!sessionValid) {
      // Limpiar cookie inválida
      res.clearCookie("auth_token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/",
      });

      res.status(401).json({
        success: false,
        error: "Sesión inválida o revocada",
      });
      return;
    }

    // 4. Agregar datos del usuario al request
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role,
    };

    // 5. Continuar al siguiente middleware/controlador
    next();
  } catch (error: any) {
    console.error("Error en autenticación:", error);
    res.status(401).json({
      success: false,
      error: "Error al verificar token",
    });
  }
};

/**
 * Middleware de verificación de rol ADMIN
 * Debe usarse DESPUÉS del middleware authenticate
 */
export const requireAdmin = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    // Verificar que el usuario esté autenticado
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: "Usuario no autenticado",
      });
      return;
    }

    // Verificar que el rol sea ADMIN
    if (req.user.role !== "ADMIN") {
      res.status(403).json({
        success: false,
        error: "Acceso denegado. Se requiere rol de administrador.",
      });
      return;
    }

    // Usuario es admin, continuar
    next();
  } catch (error: any) {
    console.error("Error verificando rol admin:", error);
    res.status(500).json({
      success: false,
      error: "Error al verificar permisos",
    });
  }
};

/**
 * Middleware de verificación de rol CLIENTE
 * Debe usarse DESPUÉS del middleware authenticate
 */
export const requireCliente = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    // Verificar que el usuario esté autenticado
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: "Usuario no autenticado",
      });
      return;
    }

    // Verificar que el rol sea CLIENTE
    if (req.user.role !== "CLIENTE") {
      res.status(403).json({
        success: false,
        error: "Acceso denegado. Se requiere rol de cliente.",
      });
      return;
    }

    // Usuario es cliente, continuar
    next();
  } catch (error: any) {
    console.error("Error verificando rol cliente:", error);
    res.status(500).json({
      success: false,
      error: "Error al verificar permisos",
    });
  }
};

/**
 * Middleware flexible que permite múltiples roles
 * Uso: requireRole(['ADMIN', 'CLIENTE'])
 */
export const requireRole = (allowedRoles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    try {
      // Verificar que el usuario esté autenticado
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Usuario no autenticado",
        });
        return;
      }

      // Verificar que el rol esté en la lista permitida
      if (!allowedRoles.includes(req.user.role)) {
        res.status(403).json({
          success: false,
          error: `Acceso denegado. Roles permitidos: ${allowedRoles.join(
            ", "
          )}`,
        });
        return;
      }

      // Usuario tiene rol permitido, continuar
      next();
    } catch (error: any) {
      console.error("Error verificando rol:", error);
      res.status(500).json({
        success: false,
        error: "Error al verificar permisos",
      });
    }
  };
};
