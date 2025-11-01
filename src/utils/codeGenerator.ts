import crypto from "crypto";

/**
 * Genera un código de verificación de 6 dígitos
 * @returns string con 6 dígitos (ej: "123456")
 */
export const generateVerificationCode = (): string => {
  // Generar número aleatorio entre 100000 y 999999
  const code = crypto.randomInt(100000, 999999);
  return code.toString();
};

/**
 * Genera una fecha de expiración para el código
 * @param minutes - Minutos hasta la expiración (por defecto 5)
 * @returns Date objeto con la fecha de expiración
 */
export const generateCodeExpiration = (minutes: number = 5): Date => {
  const now = new Date();
  now.setMinutes(now.getMinutes() + minutes);
  return now;
};

/**
 * Verifica si un código ha expirado
 * @param expiresAt - Fecha de expiración del código
 * @returns boolean - true si ha expirado, false si aún es válido
 */
export const isCodeExpired = (expiresAt: Date): boolean => {
  return new Date() > expiresAt;
};
