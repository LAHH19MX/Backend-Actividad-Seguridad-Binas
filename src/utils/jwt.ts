import jwt from "jsonwebtoken";

const JWT_SECRET =
  process.env.JWT_SECRET || "default-secret-change-in-production";

export interface JWTPayload {
  userId: string;
  email: string;
  role: string;
}

export interface TemporaryTokenPayload {
  userId: string;
  purpose:
    | "2FA"
    | "PASSWORD_RESET"
    | "PASSWORD_RESET_LINK"
    | "SECURITY_QUESTION";
  resetId?: string;
}

/**
 * Genera un JWT completo (para autenticación)
 * @param payload - Datos del usuario (userId, email, role)
 * @returns string - Token JWT
 */
export const generateToken = (payload: JWTPayload): string => {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "15m",
    algorithm: "HS256",
  } as jwt.SignOptions);
};

/**
 * Genera un refresh token
 * @param payload - Datos del usuario
 * @returns string - Refresh token
 */
export const generateRefreshToken = (payload: JWTPayload): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" } as jwt.SignOptions);
};

/**
 * Genera un token temporal (para 2FA o reset password)
 * @param payload - userId y propósito del token
 * @param expiresIn - Tiempo de expiración (default: 10 minutos)
 * @returns string - Token temporal
 */
export const generateTemporaryToken = (
  payload: TemporaryTokenPayload,
  expiresIn: string = "10m"
): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn } as jwt.SignOptions);
};

/**
 * Verifica y decodifica un JWT
 * @param token - Token a verificar
 * @returns JWTPayload | null - Payload decodificado o null si es inválido
 */
export const verifyToken = (token: string): JWTPayload | null => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JWTPayload;
    return decoded;
  } catch (error) {
    return null;
  }
};

/**
 * Verifica un token temporal
 * @param token - Token temporal a verificar
 * @returns TemporaryTokenPayload | null
 */
export const verifyTemporaryToken = (
  token: string
): TemporaryTokenPayload | null => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as TemporaryTokenPayload;
    return decoded;
  } catch (error) {
    return null;
  }
};

/**
 * Decodifica un token sin verificar (útil para debugging)
 * @param token - Token a decodificar
 * @returns any - Payload decodificado (sin verificar firma)
 */
export const decodeToken = (token: string): any => {
  try {
    return jwt.decode(token);
  } catch (error) {
    return null;
  }
};
