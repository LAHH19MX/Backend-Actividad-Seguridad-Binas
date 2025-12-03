import prisma from "../config/database";
import { sendAccountBlockedAlert } from "./emailService";

const maskEmail = (email: string): string => {
  const [local, domain] = email.split("@");
  if (!local || !domain) return "***@***.***";

  const maskedLocal =
    local.length > 2 ? `${local[0]}***${local[local.length - 1]}` : "***";

  return `${maskedLocal}@${domain}`;
};

const BLOCK_DURATION_MINUTES = 15;
const MAX_FAILED_ATTEMPTS = 3; // Máximo de intentos fallidos

export const incrementFailedAttempts = async (
  userId: string,
  email: string,
  reason: string
): Promise<{ isBlocked: boolean; attemptsLeft: number }> => {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    throw new Error("Usuario no encontrado");
  }

  const newAttempts = user.failedAttempts + 1;

  // Si llega a  intentos, bloquear cuenta
  if (newAttempts >= MAX_FAILED_ATTEMPTS) {
    const blockedUntil = new Date(
      Date.now() + BLOCK_DURATION_MINUTES * 60 * 1000
    );

    await prisma.user.update({
      where: { id: userId },
      data: {
        failedAttempts: newAttempts,
        isBlocked: true,
        blockedUntil,
      },
    });

    // Enviar email de alerta
    await sendAccountBlockedAlert(email, reason);

    console.error(`Cuenta bloqueada: ${maskEmail(email)} - Razón: ${reason}`);

    return { isBlocked: true, attemptsLeft: 0 };
  }

  // Incrementar intentos sin bloquear
  await prisma.user.update({
    where: { id: userId },
    data: { failedAttempts: newAttempts },
  });

  return {
    isBlocked: false,
    attemptsLeft: MAX_FAILED_ATTEMPTS - newAttempts,
  };
};

/**
 * Resetea los intentos fallidos de un usuario
 */
export const resetFailedAttempts = async (userId: string): Promise<void> => {
  await prisma.user.update({
    where: { id: userId },
    data: { failedAttempts: 0 },
  });
};

/**
 * Verifica si una cuenta está bloqueada
 * Si el tiempo de bloqueo ya pasó, desbloquea automáticamente
 */
export const checkIfBlocked = async (
  userId: string
): Promise<{ isBlocked: boolean; blockedUntil?: Date }> => {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    throw new Error("Usuario no encontrado");
  }

  // Si no está bloqueado, retornar inmediatamente
  if (!user.isBlocked || !user.blockedUntil) {
    return { isBlocked: false };
  }

  // Verificar si el bloqueo ya expiró
  const now = new Date();
  if (now > user.blockedUntil) {
    // Desbloquear automáticamente
    await prisma.user.update({
      where: { id: userId },
      data: {
        isBlocked: false,
        blockedUntil: null,
        failedAttempts: 0,
      },
    });

    console.log(`Cuenta desbloqueada automáticamente`);
    return { isBlocked: false };
  }

  // Aún está bloqueado
  return { isBlocked: true, blockedUntil: user.blockedUntil };
};

/**
 * Bloquea manualmente una cuenta
 */
export const blockAccount = async (
  userId: string,
  email: string,
  reason: string
): Promise<void> => {
  const blockedUntil = new Date(
    Date.now() + BLOCK_DURATION_MINUTES * 60 * 1000
  );

  await prisma.user.update({
    where: { id: userId },
    data: {
      isBlocked: true,
      blockedUntil,
      failedAttempts: MAX_FAILED_ATTEMPTS,
    },
  });

  await sendAccountBlockedAlert(email, reason);
  console.error(`Cuenta bloqueada manualmente: ${email} - Razón: ${reason}`);
};
