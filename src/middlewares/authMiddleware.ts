import { Response, NextFunction } from "express";
import { verifyToken } from "../utils/jwt";
import { AuthRequest } from "../types";

/**
 * Middleware de autenticación JWT
 * Verifica que el usuario esté autenticado mediante un token JWT válido
 */
export const authenticate = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    // 1. Obtener token del header Authorization
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      res.status(401).json({
        success: false,
        error: "No se proporcionó token de autenticación",
      });
      return;
    }

    // 2. Verificar formato "Bearer TOKEN"
    const parts = authHeader.split(" ");

    if (parts.length !== 2 || parts[0] !== "Bearer") {
      res.status(401).json({
        success: false,
        error: "Formato de token inválido. Usa: Bearer <token>",
      });
      return;
    }

    const token = parts[1];

    // 3. Verificar y decodificar token
    const decoded = verifyToken(token);

    if (!decoded) {
      res.status(401).json({
        success: false,
        error: "Token inválido o expirado",
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
    console.error("❌ Error en autenticación:", error);
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
    console.error("❌ Error verificando rol admin:", error);
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
    console.error("❌ Error verificando rol cliente:", error);
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
      console.error("❌ Error verificando rol:", error);
      res.status(500).json({
        success: false,
        error: "Error al verificar permisos",
      });
    }
  };
};
