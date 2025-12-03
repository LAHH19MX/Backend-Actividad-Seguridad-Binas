import prisma from "../config/database";
import crypto from "crypto";

/**
 * Verifica que una sesión sea válida en BD
 * @param jti - JWT ID único
 * @param token - Token completo
 * @returns boolean
 */
export const isSessionValid = async (
  jti: string,
  token: string
): Promise<boolean> => {
  try {
    // 1. Hashear el token para comparar
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    // 2. Buscar sesión en BD
    const session = await prisma.session.findUnique({
      where: { jti },
    });

    // 3. Validaciones
    if (!session) {
      console.log(`Sesión no encontrada: JTI=${jti}`);
      return false;
    }

    if (session.isRevoked) {
      console.log(`Sesión revocada: JTI=${jti}`);
      return false;
    }

    if (session.token !== tokenHash) {
      console.log(`Token no coincide con BD: JTI=${jti}`);
      return false;
    }

    if (new Date() > session.expiresAt) {
      console.log(`Sesión expirada: JTI=${jti}`);
      return false;
    }

    return true;
  } catch (error) {
    console.error("Error validando sesión:", error);
    return false;
  }
};

/**
 * Revoca una sesión específica
 * @param jti - JWT ID único
 */
export const revokeSession = async (jti: string): Promise<void> => {
  await prisma.session.update({
    where: { jti },
    data: {
      isRevoked: true,
      revokedAt: new Date(),
    },
  });

  console.log(`✅ Sesión revocada: JTI=${jti}`);
};

/**
 * Revoca TODAS las sesiones de un usuario
 * @param userId - ID del usuario
 */
export const revokeAllUserSessions = async (userId: string): Promise<void> => {
  await prisma.session.updateMany({
    where: {
      userId,
      isRevoked: false,
    },
    data: {
      isRevoked: true,
      revokedAt: new Date(),
    },
  });

  console.log(`✅ Todas las sesiones revocadas para userId=${userId}`);
};
