import { Response } from "express";
import { AuthRequest } from "../types";
import prisma from "../config/database";

/**
 * GET /api/user/profile
 * Obtener perfil del usuario autenticado
 * @access Private (requiere JWT)
 */
export const getProfile = async (
  req: AuthRequest,
  res: Response
): Promise<void> => {
  try {
    // El usuario ya está autenticado gracias al middleware
    const userId = req.user?.userId;

    if (!userId) {
      res.status(401).json({
        success: false,
        error: "Usuario no autenticado",
      });
      return;
    }

    // Buscar usuario en BD
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        role: true,
        isVerified: true,
        createdAt: true,
        updatedAt: true,
        // NO incluir password ni campos sensibles
      },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    console.log(`✅ Perfil consultado: ${user.email}`);

    res.status(200).json({
      success: true,
      message: "Perfil obtenido exitosamente",
      data: { user },
    });
  } catch (error: any) {
    console.error("❌ Error obteniendo perfil:", error);
    res.status(500).json({
      success: false,
      error: "Error al obtener perfil",
    });
  }
};

/**
 * POST /api/auth/logout
 * Cerrar sesión (invalidar token del lado del cliente)
 * @access Private (requiere JWT)
 */
export const logout = async (
  req: AuthRequest,
  res: Response
): Promise<void> => {
  try {
    const email = req.user?.email;

    console.log(`✅ Logout exitoso: ${email}`);

    // En una implementación real, aquí podrías:
    // - Agregar el token a una blacklist en Redis
    // - Incrementar tokenVersion en el usuario
    // - Registrar el evento de logout

    res.status(200).json({
      success: true,
      message: "Sesión cerrada exitosamente",
      data: {
        email,
      },
    });
  } catch (error: any) {
    console.error("❌ Error en logout:", error);
    res.status(500).json({
      success: false,
      error: "Error al cerrar sesión",
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

    console.log(`✅ Token refrescado: ${user.email}`);

    res.status(200).json({
      success: true,
      message: "Token refrescado exitosamente",
      data: {
        token: newToken,
        expiresIn: "24 horas",
      },
    });
  } catch (error: any) {
    console.error("❌ Error refrescando token:", error);
    res.status(500).json({
      success: false,
      error: "Error al refrescar token",
    });
  }
};
