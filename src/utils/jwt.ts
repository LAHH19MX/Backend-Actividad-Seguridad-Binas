import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import prisma from "../config/database";
import crypto from "crypto";

const JWT_SECRET =
  process.env.JWT_SECRET || "default-secret-change-in-production";

export interface JWTPayload {
  userId: string;
  email: string;
  role: string;
  jti: string; // 👈 AGREGADO
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
 * Genera un JWT completo Y lo guarda en BD
 * @param payload - Datos del usuario (userId, email, role)
 * @param deviceInfo - Info del dispositivo/navegador
 * @param ipAddress - IP del usuario
 * @returns Promise<string> - Token JWT
 */
export const generateToken = async (
  payload: { userId: string; email: string; role: string },
  deviceInfo?: string,
  ipAddress?: string
): Promise<string> => {
  // 1. Generar JTI único
  const jti = uuidv4();

  // 2. Crear JWT con JTI
  const token = jwt.sign(
    {
      userId: payload.userId,
      email: payload.email,
      role: payload.role,
      jti,
    },
    JWT_SECRET,
    {
      expiresIn: "15m",
      algorithm: "HS256",
    } as jwt.SignOptions
  );

  // 3. Hashear el token para guardarlo en BD
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

  // 4. Calcular fecha de expiración
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  // 5. Guardar sesión en BD
  await prisma.session.create({
    data: {
      userId: payload.userId,
      jti,
      token: tokenHash,
      deviceInfo: deviceInfo || null,
      ipAddress: ipAddress || null,
      expiresAt,
    },
  });

  return token;
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
