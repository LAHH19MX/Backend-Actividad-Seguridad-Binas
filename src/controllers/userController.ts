import { Response } from "express";
import { AuthRequest } from "../types";
import { verifyToken } from "../utils/jwt";
import { revokeSession, revokeAllUserSessions } from "../utils/sessionHelper";
import prisma from "../config/database";

const maskEmail = (email: string): string => {
  const [local, domain] = email.split("@");
  if (!local || !domain) return "***@***.***";

  const maskedLocal =
    local.length > 2 ? `${local[0]}***${local[local.length - 1]}` : "***";

  return `${maskedLocal}@${domain}`;
};

/**
 * GET /api/user/profile
 * Obtener perfil del usuario autenticado
 */
export const getProfile = async (
  req: AuthRequest,
  res: Response
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: "Usuario no autenticado",
      });
      return;
    }

    // Buscar usuario en BD
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        role: true,
        isVerified: true,
        createdAt: true,
      },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    res.status(200).json({
      success: true,
      data: { user },
    });
  } catch (error: any) {
    console.error("Error obteniendo perfil:", error);
    res.status(500).json({
      success: false,
      error: "Error al obtener perfil",
    });
  }
};

/**
 * POST /api/user/logout
 * Cerrar sesión (revoca la sesión actual)
 */
export const logout = async (
  req: AuthRequest,
  res: Response
): Promise<void> => {
  try {
    const token = req.cookies.auth_token;

    if (token) {
      // Decodificar token para obtener jti
      const decoded = verifyToken(token);

      if (decoded && decoded.jti) {
        // Revocar sesión en BD
        await revokeSession(decoded.jti);
      }
    }

    res.cookie("auth_token", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: 0,
    });

    res.cookie("csrf_token", {
      httpOnly: false,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: 0,
    });

    res.setHeader("Clear-Site-Data", '"cookies"');

    res.status(200).json({
      success: true,
      message: "Sesión cerrada exitosamente",
    });
  } catch (error: any) {
    console.error("Error en logout:", error);

    res.cookie("auth_token", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: 0,
    });

    res.cookie("csrf_token", {
      httpOnly: false,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: 0,
    });

    res.status(500).json({
      success: false,
      error: "Error al cerrar sesión",
    });
  }
};

/**
 * POST /api/user/logout-all
 * Cerrar sesión en TODOS los dispositivos
 */
export const logoutAll = async (
  req: AuthRequest,
  res: Response
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: "No autenticado",
      });
      return;
    }

    // Revocar TODAS las sesiones del usuario
    await revokeAllUserSessions(req.user.userId);

    // Eliminar cookie actual
    res.clearCookie("auth_token", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    });

    res.status(200).json({
      success: true,
      message: "Todas las sesiones cerradas exitosamente",
    });
  } catch (error: any) {
    console.error("Error en logoutAll:", error);
    res.status(500).json({
      success: false,
      error: "Error al cerrar todas las sesiones",
    });
  }
};

/**
 * POST /api/auth/refresh-token
 * Refrescar token JWT antes de que expire
 * @access Private (requiere JWT)
 */
export const refreshToken = async (
  req: AuthRequest,
  res: Response
): Promise<void> => {
  try {
    const userId = req.user?.userId;
    const email = req.user?.email;
    const role = req.user?.role;

    if (!userId || !email || !role) {
      res.status(401).json({
        success: false,
        error: "Token inválido",
      });
      return;
    }

    // Verificar que el usuario aún exista y esté activo
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        isVerified: true,
        isBlocked: true,
      },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    if (!user.isVerified) {
      res.status(403).json({
        success: false,
        error: "Cuenta no verificada",
      });
      return;
    }

    if (user.isBlocked) {
      res.status(403).json({
        success: false,
        error: "Cuenta bloqueada",
      });
      return;
    }

    // Generar nuevo token
    const { generateToken } = await import("../utils/jwt");
    const newToken = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    console.log(`Token refrescado: ${maskEmail(user.email)}`);

    res.status(200).json({
      success: true,
      message: "Token refrescado exitosamente",
      data: {
        token: newToken,
        expiresIn: "24 horas",
      },
    });
  } catch (error: any) {
    console.error("Error refrescando token:", error);
    res.status(500).json({
      success: false,
      error: "Error al refrescar token",
    });
  }
};
