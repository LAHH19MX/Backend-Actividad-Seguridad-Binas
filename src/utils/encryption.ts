import bcrypt from "bcrypt";

const SALT_ROUNDS = 10;

/**
 * Encripta una contraseña o código usando bcrypt
 * @param text - Texto a encriptar
 * @returns Promise<string> - Hash encriptado
 */
export const hashText = async (text: string): Promise<string> => {
  return await bcrypt.hash(text, SALT_ROUNDS);
};

/**
 * Compara un texto plano con un hash
 * @param plainText - Texto sin encriptar
 * @param hashedText - Hash para comparar
 * @returns Promise<boolean> - true si coinciden, false si no
 */
export const compareHash = async (
  plainText: string,
  hashedText: string
): Promise<boolean> => {
  return await bcrypt.compare(plainText, hashedText);
};

/**
 * Encripta una contraseña
 * @param password - Contraseña a encriptar
 * @returns Promise<string> - Hash de la contraseña
 */
export const hashPassword = async (password: string): Promise<string> => {
  return await hashText(password);
};

/**
 * Verifica una contraseña contra su hash
 * @param password - Contraseña ingresada
 * @param hashedPassword - Hash almacenado
 * @returns Promise<boolean> - true si la contraseña es correcta
 */
export const verifyPassword = async (
  password: string,
  hashedPassword: string
): Promise<boolean> => {
  return await compareHash(password, hashedPassword);
};
