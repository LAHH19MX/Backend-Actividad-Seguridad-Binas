import { Request, Response } from "express";
import prisma from "../config/database";
import {
  RegisterDTO,
  VerifyRegistrationDTO,
  ApiResponse,
  ResetPasswordWithLinkDTO,
} from "../types";
import {
  isValidEmail,
  isValidPhone,
  isValidPassword,
  isValidName,
  isValidCode,
  sanitizeEmail,
  sanitizeName,
  sanitizePhone,
  getPasswordErrorMessage,
} from "../utils/validators";
import { hashPassword, hashText } from "../utils/encryption";
import {
  generateVerificationCode,
  generateCodeExpiration,
} from "../utils/codeGenerator";
import { sendVerificationCode } from "../services/emailService";
import { sendVerificationCodeSMS } from "../services/smsService";
import { AppError } from "../middlewares/errorHandler";
import {
  checkIfBlocked,
  incrementFailedAttempts,
  resetFailedAttempts,
} from "../services/accountBlockService";
import { securityLogger } from "../middlewares/logger";
import { send2FACode, sendPasswordResetCode } from "../services/emailService";
import {
  send2FACodeSMS,
  sendPasswordResetCodeSMS,
} from "../services/smsService";
import {
  LoginDTO,
  Resend2FADTO,
  Verify2FADTO,
  ForgotPasswordDTO,
  VerifyRecoveryCodeDTO,
  ResetPasswordDTO,
} from "../types/index";
import { generateTemporaryToken, verifyTemporaryToken } from "../utils/jwt";
import { verifyPassword, compareHash } from "../utils/encryption";
import crypto from "crypto";

const maskEmail = (email: string): string => {
  const [local, domain] = email.split("@");
  if (!local || !domain) return "***@***.***";

  const maskedLocal =
    local.length > 2 ? `${local[0]}***${local[local.length - 1]}` : "***";

  return `${maskedLocal}@${domain}`;
};

/**
 * REGISTRO - POST /api/auth/register
 */
export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const {
      name,
      email,
      phone,
      password,
      confirmPassword,
      securityQuestion,
      securityAnswer,
    } = req.body;

    // 1. Validar que todos los campos existan
    if (
      !name ||
      !email ||
      !phone ||
      !password ||
      !confirmPassword ||
      !securityQuestion ||
      !securityAnswer
    ) {
      res.status(400).json({
        success: false,
        error:
          "Todos los campos son obligatorios, incluyendo la pregunta de seguridad",
      });
      return;
    }

    // 2. Sanitizar datos
    const sanitizedEmail = sanitizeEmail(email);
    const sanitizedName = sanitizeName(name);
    const sanitizedPhone = sanitizePhone(phone);

    // 3. Validar formato de nombre
    if (!isValidName(sanitizedName)) {
      res.status(400).json({
        success: false,
        error: "El nombre debe tener entre 2 y 100 caracteres",
      });
      return;
    }

    // 4. Validar formato de email
    if (!isValidEmail(sanitizedEmail)) {
      res.status(400).json({
        success: false,
        error: "El formato del email es inválido",
      });
      return;
    }

    // 5. Validar formato de teléfono
    if (!isValidPhone(sanitizedPhone)) {
      res.status(400).json({
        success: false,
        error:
          "El formato del teléfono es inválido. Debe ser formato internacional (ej: +521234567890)",
      });
      return;
    }

    // 6. Validar que las contraseñas coincidan
    if (password !== confirmPassword) {
      res.status(400).json({
        success: false,
        error: "Las contraseñas no coinciden",
      });
      return;
    }

    // 7. Validar fortaleza de contraseña
    if (!isValidPassword(password)) {
      res.status(400).json({
        success: false,
        error: getPasswordErrorMessage(),
      });
      return;
    }

    // 8. Validar pregunta de seguridad
    const {
      isValidSecurityQuestion,
      isValidSecurityAnswer,
      sanitizeSecurityAnswer,
    } = await import("../utils/validators");

    if (!isValidSecurityQuestion(securityQuestion)) {
      res.status(400).json({
        success: false,
        error: "La pregunta de seguridad seleccionada no es válida",
      });
      return;
    }

    // 9. Validar respuesta de seguridad
    if (!isValidSecurityAnswer(securityAnswer)) {
      res.status(400).json({
        success: false,
        error: "La respuesta de seguridad debe tener entre 2 y 100 caracteres",
      });
      return;
    }

    // 10. Verificar que el email no exista
    const existingEmail = await prisma.user.findUnique({
      where: { email: sanitizedEmail },
    });

    if (existingEmail) {
      res.status(409).json({
        success: false,
        error: "El email ya está registrado",
      });
      return;
    }

    // 11. Verificar que el teléfono no exista
    const existingPhone = await prisma.user.findUnique({
      where: { phone: sanitizedPhone },
    });

    if (existingPhone) {
      res.status(409).json({
        success: false,
        error: "El teléfono ya está registrado",
      });
      return;
    }

    // 12. Encriptar contraseña
    const hashedPassword = await hashPassword(password);

    // 13. Sanitizar y encriptar respuesta de seguridad
    const sanitizedAnswer = sanitizeSecurityAnswer(securityAnswer);
    const hashedSecurityAnswer = await hashPassword(sanitizedAnswer);

    // 14. Crear usuario en BD (sin verificar)
    const newUser = await prisma.user.create({
      data: {
        name: sanitizedName,
        email: sanitizedEmail,
        phone: sanitizedPhone,
        password: hashedPassword,
        role: "CLIENTE",
        isVerified: false,
        securityQuestion: securityQuestion,
        securityAnswer: hashedSecurityAnswer,
      },
    });

    // 15. Generar código para email
    const emailCode = generateVerificationCode();
    const hashedEmailCode = await hashText(emailCode);
    const emailCodeExpiration = generateCodeExpiration(5); // 5 minutos

    // 16. Guardar código en BD
    await prisma.verificationCode.create({
      data: {
        userId: newUser.id,
        code: hashedEmailCode,
        type: "REGISTRATION_EMAIL",
        expiresAt: emailCodeExpiration,
      },
    });

    // 17. Enviar código por email
    const emailSent = await sendVerificationCode(sanitizedEmail, emailCode);

    if (!emailSent) {
      console.error("⚠️  Error enviando email de verificación");
    }

    // 18. Registrar intento de registro exitoso
    await prisma.loginAttempt.create({
      data: {
        userId: newUser.id,
        email: sanitizedEmail,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        success: true,
        failReason: null,
      },
    });

    // 19. Responder con éxito
    res.status(201).json({
      success: true,
      message:
        "Usuario registrado. Hemos enviado un código de verificación a tu email.",
      data: {
        email: sanitizedEmail,
        phone: sanitizedPhone,
        emailSent,
      },
    });
  } catch (error: any) {
    console.error("❌ Error en registro:", error);
    res.status(500).json({
      success: false,
      error: "Error al registrar usuario",
    });
  }
};

/**
 * VERIFICAR REGISTRO
 */
export const verifyRegistration = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { email, emailCode }: VerifyRegistrationDTO = req.body;

    // 1. Validar que todos los campos existan
    if (!email || !emailCode) {
      res.status(400).json({
        success: false,
        error: "Email y código son obligatorios",
      });
      return;
    }

    // 2. Sanitizar email
    const sanitizedEmail = sanitizeEmail(email);

    // 3. Validar formato de código (6 dígitos)
    if (!isValidCode(emailCode)) {
      res.status(400).json({
        success: false,
        error: "El código debe ser de 6 dígitos",
      });
      return;
    }

    // 4. Buscar usuario por email
    const user = await prisma.user.findUnique({
      where: { email: sanitizedEmail },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    // 5. Verificar si ya está verificado
    if (user.isVerified) {
      res.status(400).json({
        success: false,
        error: "El usuario ya está verificado",
      });
      return;
    }

    // 6. Buscar código de email
    const storedEmailCode = await prisma.verificationCode.findFirst({
      where: {
        userId: user.id,
        type: "REGISTRATION_EMAIL",
        isUsed: false,
      },
      orderBy: { createdAt: "desc" },
    });

    if (!storedEmailCode) {
      res.status(400).json({
        success: false,
        error: "Código de email no encontrado o ya fue usado",
      });
      return;
    }

    // 7. Verificar si el código expiró
    const now = new Date();
    if (now > storedEmailCode.expiresAt) {
      res.status(400).json({
        success: false,
        error: "El código de email ha expirado",
      });
      return;
    }

    // 8. Verificar código de email
    const { compareHash } = await import("../utils/encryption");
    const isEmailCodeValid = await compareHash(emailCode, storedEmailCode.code);

    if (!isEmailCodeValid) {
      res.status(400).json({
        success: false,
        error: "El código de email es incorrecto",
      });
      return;
    }

    // 9. Actualizar usuario a verificado
    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true },
    });

    // 10. Marcar código como usado
    await prisma.verificationCode.updateMany({
      where: {
        userId: user.id,
        type: "REGISTRATION_EMAIL",
      },
      data: { isUsed: true },
    });

    // 11. Registrar verificación exitosa
    await prisma.loginAttempt.create({
      data: {
        userId: user.id,
        email: sanitizedEmail,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        success: true,
        failReason: null,
      },
    });

    console.log(
      `Usuario verificado exitosamente: ${maskEmail(sanitizedEmail)}`
    );

    // 12. Responder con éxito
    res.status(200).json({
      success: true,
      message: "Cuenta verificada exitosamente. Ahora puedes iniciar sesión.",
      data: {
        email: sanitizedEmail,
        isVerified: true,
      },
    });
  } catch (error: any) {
    console.error("Error en verificación de registro:", error);
    if (error instanceof AppError) {
      res.status(error.statusCode).json({
        success: false,
        error: error.message,
      });
      return;
    }

    res.status(500).json({
      success: false,
      error: "Error al verificar cuenta",
    });
  }
};

/**
 * LOGIN  - POST /api/auth/login
 */
export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password }: LoginDTO = req.body;

    // 1. Validar que todos los campos existan
    if (!email || !password) {
      res.status(400).json({
        success: false,
        error: "Email y contraseña son obligatorios",
      });
      return;
    }

    // 2. Sanitizar email
    const sanitizedEmail = sanitizeEmail(email);

    // 3. Validar formato de email
    if (!isValidEmail(sanitizedEmail)) {
      res.status(400).json({
        success: false,
        error: "Usuario o contraseña incorrectos",
      });
      return;
    }

    // 4. Buscar usuario por email
    const user = await prisma.user.findUnique({
      where: { email: sanitizedEmail },
    });

    // 5. Si no existe, retornar error genérico (seguridad)
    if (!user) {
      securityLogger.logFailedLogin(
        sanitizedEmail,
        req.ip || "unknown",
        "Usuario no encontrado"
      );

      res.status(401).json({
        success: false,
        error: "Usuario o contraseña incorrectos",
      });
      return;
    }

    // 6. Verificar si usuario está verificado
    if (!user.isVerified) {
      // Invalidar códigos anteriores
      await prisma.verificationCode.updateMany({
        where: {
          userId: user.id,
          type: "REGISTRATION_EMAIL",
          isUsed: false,
        },
        data: { isUsed: true },
      });

      // Generar nuevo código para email
      const emailCode = generateVerificationCode();
      const hashedEmailCode = await hashText(emailCode);
      const emailCodeExpiration = generateCodeExpiration(5); // 5 minutos

      // Guardar código en BD
      await prisma.verificationCode.create({
        data: {
          userId: user.id,
          code: hashedEmailCode,
          type: "REGISTRATION_EMAIL",
          expiresAt: emailCodeExpiration,
        },
      });

      // Enviar código por email
      const emailSent = await sendVerificationCode(sanitizedEmail, emailCode);

      if (!emailSent) {
        console.error("Error enviando código de verificación");
      }

      console.log(
        `Cuenta no verificada. Código reenviado a: ${maskEmail(sanitizedEmail)}`
      );

      res.status(403).json({
        success: false,
        error:
          "Cuenta no verificada. Hemos enviado un nuevo código a tu email.",
        requiresVerification: true,
        data: {
          email: sanitizedEmail,
          phone: user.phone,
          emailSent,
        },
      });
      return;
    }

    // 7. Verificar si la cuenta está bloqueada
    const blockStatus = await checkIfBlocked(user.id);

    if (blockStatus.isBlocked) {
      const timeLeft = blockStatus.blockedUntil
        ? Math.ceil(
            (blockStatus.blockedUntil.getTime() - Date.now()) / 1000 / 60
          )
        : 10;

      res.status(403).json({
        success: false,
        error: `Cuenta bloqueada temporalmente. Intenta nuevamente en ${timeLeft} minutos.`,
        isBlocked: true,
        blockedUntil: blockStatus.blockedUntil,
      });
      return;
    }

    // 8. Verificar contraseña con bcrypt
    const isPasswordValid = await verifyPassword(password, user.password);

    // 9. Si la contraseña es INCORRECTA
    if (!isPasswordValid) {
      // Incrementar intentos fallidos
      const attemptResult = await incrementFailedAttempts(
        user.id,
        sanitizedEmail,
        "Contraseña incorrecta"
      );

      // Registrar intento fallido
      await prisma.loginAttempt.create({
        data: {
          userId: user.id,
          email: sanitizedEmail,
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"],
          success: false,
          failReason: "Contraseña incorrecta",
        },
      });

      securityLogger.logFailedLogin(
        sanitizedEmail,
        req.ip || "unknown",
        "Contraseña incorrecta"
      );

      // Si se bloqueó la cuenta
      if (attemptResult.isBlocked) {
        securityLogger.logAccountBlocked(sanitizedEmail, req.ip || "unknown");

        res.status(403).json({
          success: false,
          error:
            "Demasiados intentos fallidos. Tu cuenta ha sido bloqueada temporalmente. Se ha enviado un email de alerta.",
          isBlocked: true,
        });
        return;
      }

      // Si aún no se bloquea
      res.status(401).json({
        success: false,
        error: "Usuario o contraseña incorrectos",
        attemptsLeft: attemptResult.attemptsLeft,
      });
      return;
    }

    // 10. Si la contraseña es CORRECTA ✅

    // Resetear intentos fallidos
    await resetFailedAttempts(user.id);

    // 11. Generar código 2FA
    const twoFACode = generateVerificationCode();
    const hashedTwoFACode = await hashText(twoFACode);
    const twoFAExpiration = generateCodeExpiration(5); // 5 minutos

    // 12. Guardar código 2FA en BD
    await prisma.verificationCode.create({
      data: {
        userId: user.id,
        code: hashedTwoFACode,
        type: "TWO_FACTOR",
        expiresAt: twoFAExpiration,
      },
    });

    // 13. Enviar código 2FA por EMAIL (por defecto)
    const emailSent = await send2FACode(sanitizedEmail, twoFACode);

    if (!emailSent) {
      console.error("⚠️  Error enviando código 2FA por email");
    }

    // 14. Generar token temporal (NO es el JWT final)
    const tempToken = generateTemporaryToken(
      {
        userId: user.id,
        purpose: "2FA",
      },
      "10m" // Token válido por 10 minutos
    );

    // 15. Registrar login parcial exitoso
    await prisma.loginAttempt.create({
      data: {
        userId: user.id,
        email: sanitizedEmail,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        success: true,
        failReason: null,
      },
    });

    console.log(`Credenciales válidas para: ${maskEmail(sanitizedEmail)}`);
    console.log(`Código 2FA enviado por email`);

    // 16. Responder con token temporal
    res.status(200).json({
      success: true,
      message: "Credenciales válidas. Código 2FA enviado a tu email.",
      data: {
        tempToken,
        email: sanitizedEmail,
        phone: user.phone,
        requires2FA: true,
        emailSent,
      },
    });
  } catch (error: any) {
    console.error("❌ Error en login:", error);
    res.status(500).json({
      success: false,
      error: "Error al iniciar sesión",
    });
  }
};

export const resend2FA = async (req: Request, res: Response): Promise<void> => {
  try {
    const { tempToken, method }: Resend2FADTO = req.body;

    // 1. Validar que todos los campos existan
    if (!tempToken || !method) {
      res.status(400).json({
        success: false,
        error: "Token temporal y método son obligatorios",
      });
      return;
    }

    // 2. Validar que el método sea válido
    if (method !== "email") {
      res.status(400).json({
        success: false,
        error: "Método inválido. Solo se permite 'email'",
      });
      return;
    }

    // 3. Verificar token temporal
    const decoded = verifyTemporaryToken(tempToken);

    if (!decoded || decoded.purpose !== "2FA") {
      res.status(401).json({
        success: false,
        error: "Token temporal inválido o expirado",
      });
      return;
    }

    // 4. Buscar usuario
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    // 5. Verificar si la cuenta está bloqueada
    const blockStatus = await checkIfBlocked(user.id);

    if (blockStatus.isBlocked) {
      const timeLeft = blockStatus.blockedUntil
        ? Math.ceil(
            (blockStatus.blockedUntil.getTime() - Date.now()) / 1000 / 60
          )
        : 10;

      res.status(403).json({
        success: false,
        error: `Cuenta bloqueada temporalmente. Intenta nuevamente en ${timeLeft} minutos.`,
      });
      return;
    }

    // 6. Invalidar código anterior (marcarlo como usado)
    await prisma.verificationCode.updateMany({
      where: {
        userId: user.id,
        type: "TWO_FACTOR",
        isUsed: false,
      },
      data: { isUsed: true },
    });

    // 7. Generar nuevo código 2FA
    const newCode = generateVerificationCode();
    const hashedCode = await hashText(newCode);
    const codeExpiration = generateCodeExpiration(5); // 5 minutos

    // 8. Guardar nuevo código en BD
    await prisma.verificationCode.create({
      data: {
        userId: user.id,
        code: hashedCode,
        type: "TWO_FACTOR",
        expiresAt: codeExpiration,
      },
    });

    // 9. Enviar código por email
    const sent = await send2FACode(user.email, newCode);

    if (!sent) {
      console.error(`⚠️  Error enviando código 2FA por email`);
    }

    console.log(`Código 2FA reenviado por email a: ${maskEmail(user.email)}`);

    // 10. Responder con éxito
    res.status(200).json({
      success: true,
      message: "Código 2FA reenviado por email",
      data: {
        method: "email",
        sent,
        expiresIn: "5 minutos",
      },
    });
  } catch (error: any) {
    console.error("❌ Error reenviando código 2FA:", error);
    res.status(500).json({
      success: false,
      error: "Error al reenviar código",
    });
  }
};

export const verify2FA = async (req: Request, res: Response): Promise<void> => {
  try {
    const { tempToken, code }: Verify2FADTO = req.body;

    // 1. Validar que todos los campos existan
    if (!tempToken || !code) {
      res.status(400).json({
        success: false,
        error: "Token temporal y código son obligatorios",
      });
      return;
    }

    // 2. Validar formato del código (6 dígitos)
    if (!isValidCode(code)) {
      res.status(400).json({
        success: false,
        error: "El código debe ser de 6 dígitos",
      });
      return;
    }

    // 3. Verificar token temporal
    const decoded = verifyTemporaryToken(tempToken);

    if (!decoded || decoded.purpose !== "2FA") {
      res.status(401).json({
        success: false,
        error: "Token temporal inválido o expirado",
      });
      return;
    }

    // 4. Buscar usuario
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    // 5. Verificar si la cuenta está bloqueada
    const blockStatus = await checkIfBlocked(user.id);

    if (blockStatus.isBlocked) {
      const timeLeft = blockStatus.blockedUntil
        ? Math.ceil(
            (blockStatus.blockedUntil.getTime() - Date.now()) / 1000 / 60
          )
        : 10;

      res.status(403).json({
        success: false,
        error: `Cuenta bloqueada temporalmente. Intenta nuevamente en ${timeLeft} minutos.`,
      });
      return;
    }

    // 6. Buscar código 2FA más reciente
    const storedCode = await prisma.verificationCode.findFirst({
      where: {
        userId: user.id,
        type: "TWO_FACTOR",
        isUsed: false,
      },
      orderBy: { createdAt: "desc" },
    });

    if (!storedCode) {
      res.status(400).json({
        success: false,
        error: "Código no encontrado o ya fue usado",
      });
      return;
    }

    // 7. Verificar si el código expiró
    const now = new Date();
    if (now > storedCode.expiresAt) {
      res.status(400).json({
        success: false,
        error: "El código ha expirado. Solicita uno nuevo.",
      });
      return;
    }

    // 8. Verificar código con bcrypt
    const isCodeValid = await compareHash(code, storedCode.code);

    // 9. Si el código es INCORRECTO ❌
    if (!isCodeValid) {
      // Incrementar intentos fallidos
      const attemptResult = await incrementFailedAttempts(
        user.id,
        user.email,
        "Código 2FA incorrecto"
      );

      // Registrar intento fallido
      await prisma.loginAttempt.create({
        data: {
          userId: user.id,
          email: user.email,
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"],
          success: false,
          failReason: "Código 2FA incorrecto",
        },
      });

      securityLogger.logFailedLogin(
        user.email,
        req.ip || "unknown",
        "Código 2FA incorrecto"
      );

      // Si se bloqueó la cuenta
      if (attemptResult.isBlocked) {
        securityLogger.logAccountBlocked(user.email, req.ip || "unknown");

        res.status(403).json({
          success: false,
          error:
            "Demasiados intentos fallidos. Tu cuenta ha sido bloqueada temporalmente. Se ha enviado un email de alerta.",
          isBlocked: true,
        });
        return;
      }

      // Si aún no se bloquea
      res.status(401).json({
        success: false,
        error: "Código incorrecto",
        attemptsLeft: attemptResult.attemptsLeft,
      });
      return;
    }

    // 10. Si el código es CORRECTO ✅✅✅

    // Resetear intentos fallidos
    await resetFailedAttempts(user.id);

    // 11. Marcar código como usado
    await prisma.verificationCode.update({
      where: { id: storedCode.id },
      data: { isUsed: true },
    });

    // 12. Generar JWT completo con rol
    const { generateToken } = await import("../utils/jwt");
    const jwtToken = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    // 13. Registrar login exitoso
    await prisma.loginAttempt.create({
      data: {
        userId: user.id,
        email: user.email,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        success: true,
        failReason: null,
      },
    });

    securityLogger.logSuccessfulLogin(user.email, req.ip || "unknown");

    console.log(`Login exitoso completo: ${maskEmail(user.email)}`);

    // 14. Responder con JWT + datos del usuario
    res.status(200).json({
      success: true,
      message: "Login exitoso",
      data: {
        token: jwtToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          phone: user.phone,
        },
      },
    });
  } catch (error: any) {
    console.error("❌ Error en verificación 2FA:", error);
    res.status(500).json({
      success: false,
      error: "Error al verificar código",
    });
  }
};

export const forgotPassword = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { email, method }: { email: string; method?: "code" | "link" } =
      req.body;

    // 1. Validar que el email exista
    if (!email) {
      res.status(400).json({
        success: false,
        error: "El email es obligatorio",
      });
      return;
    }

    // 2. Validar método (por defecto "code" para mantener compatibilidad)
    const recoveryMethod = method || "code";

    if (recoveryMethod !== "code" && recoveryMethod !== "link") {
      res.status(400).json({
        success: false,
        error: "Método inválido. Usa 'code' o 'link'",
      });
      return;
    }

    // 3. Sanitizar email
    const sanitizedEmail = sanitizeEmail(email);

    // 4. Validar formato de email
    if (!isValidEmail(sanitizedEmail)) {
      res.status(400).json({
        success: false,
        error: "El formato del email es inválido",
      });
      return;
    }

    // 5. Buscar usuario por email
    const user = await prisma.user.findUnique({
      where: { email: sanitizedEmail },
    });

    // 6. Si no existe, responder éxito (seguridad: no revelar si email existe)
    if (!user) {
      res.status(200).json({
        success: true,
        message:
          "Si el email está registrado, recibirás un código o enlace de recuperación.",
      });
      return;
    }

    // 7. Verificar si hay bloqueo de recuperación (separado del bloqueo de login)
    if (user.recoveryBlockedUntil && new Date() < user.recoveryBlockedUntil) {
      const timeLeft = Math.ceil(
        (user.recoveryBlockedUntil.getTime() - Date.now()) / 1000 / 60
      );

      res.status(403).json({
        success: false,
        error: `Demasiados intentos de recuperación. Intenta nuevamente en ${timeLeft} minutos.`,
        isBlocked: true,
      });
      return;
    }

    // 8. Si el bloqueo ya expiró, limpiarlo
    if (user.recoveryBlockedUntil && new Date() >= user.recoveryBlockedUntil) {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          recoveryAttempts: 0,
          recoveryBlockedUntil: null,
        },
      });
    }

    // 9A. MÉTODO: CÓDIGO (flujo actual, sin cambios)
    if (recoveryMethod === "code") {
      // Generar código de recuperación
      const recoveryCode = generateVerificationCode();
      const hashedCode = await hashText(recoveryCode);
      const codeExpiration = generateCodeExpiration(5); // 5 minutos

      // Guardar código en BD
      await prisma.verificationCode.create({
        data: {
          userId: user.id,
          code: hashedCode,
          type: "PASSWORD_RESET",
          expiresAt: codeExpiration,
        },
      });

      // Enviar código por EMAIL
      const emailSent = await sendPasswordResetCode(
        sanitizedEmail,
        recoveryCode
      );

      if (!emailSent) {
        console.error("⚠️  Error enviando código de recuperación por email");
      }

      // Generar token temporal para siguiente paso
      const tempToken = generateTemporaryToken(
        {
          userId: user.id,
          purpose: "PASSWORD_RESET",
        },
        "10m"
      );

      console.log(
        `Código de recuperación enviado a: ${maskEmail(sanitizedEmail)}`
      );

      res.status(200).json({
        success: true,
        message: "Código de recuperación enviado a tu email.",
        data: {
          method: "code",
          tempToken,
          email: sanitizedEmail,
          phone: user.phone,
          emailSent,
        },
      });
      return;
    }

    // 9B. MÉTODO: ENLACE (MODIFICADO)
    if (recoveryMethod === "link") {
      // Generar token privado (se guarda en BD, NO se envía)
      const resetToken = crypto.randomBytes(32).toString("hex");

      // Generar ID público (se envía en el enlace)
      const resetId = crypto.randomBytes(16).toString("hex"); // 👈 NUEVO

      const resetTokenExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutos

      // Guardar ambos en BD
      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetToken, // Token privado
          resetId, // ID público 👈 NUEVO
          resetTokenExpiry,
        },
      });

      // Enviar enlace con resetId (NO con resetToken) 👈 CAMBIO
      const { sendPasswordResetLink } = await import(
        "../services/emailService"
      );
      const emailSent = await sendPasswordResetLink(sanitizedEmail, resetId);

      if (!emailSent) {
        console.error("⚠️  Error enviando enlace de recuperación por email");
      }

      console.log(
        `Enlace de recuperación enviado a: ${maskEmail(sanitizedEmail)}`
      );

      res.status(200).json({
        success: true,
        message:
          "Enlace de recuperación enviado a tu email. Válido por 5 minutos.",
        data: {
          method: "link",
          email: sanitizedEmail,
          emailSent,
          expiresIn: "5 minutos",
        },
      });
      return;
    }
  } catch (error: any) {
    console.error("Error en recuperación de contraseña:", error);
    res.status(500).json({
      success: false,
      error: "Error al solicitar recuperación de contraseña",
    });
  }
};

/**
 * INICIAR RECUPERACIÓN CON PREGUNTA SECRETA - POST /api/auth/forgot-password-security
 */
export const forgotPasswordWithSecurity = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { email }: { email: string } = req.body;

    // 1. Validar que el email exista
    if (!email) {
      res.status(400).json({
        success: false,
        error: "El email es obligatorio",
      });
      return;
    }

    // 2. Sanitizar email
    const sanitizedEmail = sanitizeEmail(email);

    // 3. Validar formato de email
    if (!isValidEmail(sanitizedEmail)) {
      res.status(400).json({
        success: false,
        error: "El formato del email es inválido",
      });
      return;
    }

    // 4. Buscar usuario por email
    const user = await prisma.user.findUnique({
      where: { email: sanitizedEmail },
      select: {
        id: true,
        email: true,
        securityQuestion: true,
        securityAnswer: true,
        securityAnswerBlockedUntil: true,
      },
    });

    // 5. Si no existe, responder mensaje genérico (NO revelar que no existe)
    if (!user) {
      res.status(200).json({
        success: true,
        message:
          "Si el email está registrado y tiene pregunta de seguridad configurada, podrás responderla.",
        data: {
          hasSecurityQuestion: false, // No revelar si existe
        },
      });
      return;
    }

    // 6. Verificar si tiene pregunta de seguridad configurada
    if (!user.securityQuestion || !user.securityAnswer) {
      res.status(200).json({
        success: true,
        message:
          "Si el email está registrado y tiene pregunta de seguridad configurada, podrás responderla.",
        data: {
          hasSecurityQuestion: false,
        },
      });
      return;
    }

    // 7. Verificar si hay bloqueo de intentos de respuesta
    if (
      user.securityAnswerBlockedUntil &&
      new Date() < user.securityAnswerBlockedUntil
    ) {
      const timeLeft = Math.ceil(
        (user.securityAnswerBlockedUntil.getTime() - Date.now()) / 1000 / 60
      );

      res.status(403).json({
        success: false,
        error: `Demasiados intentos fallidos. Intenta nuevamente en ${timeLeft} minutos.`,
        isBlocked: true,
      });
      return;
    }

    // 8. Si el bloqueo ya expiró, limpiarlo
    if (
      user.securityAnswerBlockedUntil &&
      new Date() >= user.securityAnswerBlockedUntil
    ) {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          securityAnswerAttempts: 0,
          securityAnswerBlockedUntil: null,
        },
      });
    }

    // 9. Generar token temporal para siguiente paso
    const tempToken = generateTemporaryToken(
      {
        userId: user.id,
        purpose: "SECURITY_QUESTION",
      },
      "10m"
    );

    // 10. Obtener el texto de la pregunta desde SECURITY_QUESTIONS
    const { SECURITY_QUESTIONS } = await import("../types");
    const questionData = SECURITY_QUESTIONS.find(
      (q) => q.id === user.securityQuestion
    );
    const questionText = questionData
      ? questionData.question
      : user.securityQuestion;

    console.log(
      `Pregunta de seguridad solicitada para: ${maskEmail(sanitizedEmail)}`
    );

    // 11. Responder con la pregunta de seguridad
    res.status(200).json({
      success: true,
      message: "Responde tu pregunta de seguridad para continuar.",
      data: {
        hasSecurityQuestion: true,
        tempToken,
        securityQuestion: questionText,
        email: sanitizedEmail,
      },
    });
  } catch (error: any) {
    console.error("Error en recuperación con pregunta secreta:", error);
    res.status(500).json({
      success: false,
      error: "Error al solicitar pregunta de seguridad",
    });
  }
};

/**
 * VERIFICAR RESPUESTA DE PREGUNTA SECRETA - POST /api/auth/verify-security-answer
 */
export const verifySecurityAnswer = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { tempToken, answer }: { tempToken: string; answer: string } =
      req.body;

    // 1. Validar que todos los campos existan
    if (!tempToken || !answer) {
      res.status(400).json({
        success: false,
        error: "Token y respuesta son obligatorios",
      });
      return;
    }

    // 2. Validar formato de respuesta
    const { isValidSecurityAnswer, sanitizeSecurityAnswer } = await import(
      "../utils/validators"
    );

    if (!isValidSecurityAnswer(answer)) {
      res.status(400).json({
        success: false,
        error: "La respuesta debe tener entre 2 y 100 caracteres",
      });
      return;
    }

    // 3. Verificar token temporal
    const decoded = verifyTemporaryToken(tempToken);

    if (!decoded || decoded.purpose !== "SECURITY_QUESTION") {
      res.status(401).json({
        success: false,
        error: "Token inválido o expirado",
      });
      return;
    }

    // 4. Buscar usuario
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        securityAnswer: true,
        securityAnswerAttempts: true,
        securityAnswerBlockedUntil: true,
      },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    // 5. Verificar si la cuenta está bloqueada
    if (
      user.securityAnswerBlockedUntil &&
      new Date() < user.securityAnswerBlockedUntil
    ) {
      const timeLeft = Math.ceil(
        (user.securityAnswerBlockedUntil.getTime() - Date.now()) / 1000 / 60
      );

      res.status(403).json({
        success: false,
        error: `Demasiados intentos fallidos. Intenta nuevamente en ${timeLeft} minutos.`,
        isBlocked: true,
      });
      return;
    }

    // 6. Sanitizar respuesta del usuario
    const sanitizedAnswer = sanitizeSecurityAnswer(answer);

    // 7. Verificar respuesta con bcrypt
    const isAnswerValid = await verifyPassword(
      sanitizedAnswer,
      user.securityAnswer!
    );

    // 8. Si la respuesta es INCORRECTA
    if (!isAnswerValid) {
      const newAttempts = user.securityAnswerAttempts + 1;

      // Si alcanza 3 intentos, bloquear por 10 minutos
      if (newAttempts >= 3) {
        const blockedUntil = new Date(Date.now() + 10 * 60 * 1000);

        await prisma.user.update({
          where: { id: user.id },
          data: {
            securityAnswerAttempts: newAttempts,
            securityAnswerBlockedUntil: blockedUntil,
          },
        });

        securityLogger.logFailedLogin(
          user.email,
          req.ip || "unknown",
          "Pregunta de seguridad - Bloqueado"
        );

        res.status(403).json({
          success: false,
          error:
            "Demasiados intentos fallidos. Cuenta bloqueada temporalmente por 10 minutos.",
          isBlocked: true,
        });
        return;
      }

      // Incrementar intentos sin bloquear
      await prisma.user.update({
        where: { id: user.id },
        data: {
          securityAnswerAttempts: newAttempts,
        },
      });

      securityLogger.logFailedLogin(
        user.email,
        req.ip || "unknown",
        "Respuesta de pregunta de seguridad incorrecta"
      );

      res.status(401).json({
        success: false,
        error: "Respuesta incorrecta",
        attemptsLeft: 3 - newAttempts,
      });
      return;
    }

    // 9. Si la respuesta es CORRECTA
    // Resetear intentos fallidos
    await prisma.user.update({
      where: { id: user.id },
      data: {
        securityAnswerAttempts: 0,
        securityAnswerBlockedUntil: null,
      },
    });

    // 10. Generar código de recuperación (igual que el flujo de código actual)
    const recoveryCode = generateVerificationCode();
    const hashedCode = await hashText(recoveryCode);
    const codeExpiration = generateCodeExpiration(5); // 5 minutos

    // 11. Guardar código en BD
    await prisma.verificationCode.create({
      data: {
        userId: user.id,
        code: hashedCode,
        type: "PASSWORD_RESET",
        expiresAt: codeExpiration,
      },
    });

    // 12. Enviar código por email
    const emailSent = await sendPasswordResetCode(user.email, recoveryCode);

    if (!emailSent) {
      console.error("Error enviando código de recuperación por email");
    }

    // 13. Generar token temporal para siguiente paso (verificar código)
    const resetToken = generateTemporaryToken(
      {
        userId: user.id,
        purpose: "PASSWORD_RESET",
      },
      "10m"
    );

    console.log(
      `Pregunta de seguridad correcta. Código enviado a: ${maskEmail(
        user.email
      )}`
    );

    // 14. Responder con éxito y token para siguiente paso
    res.status(200).json({
      success: true,
      message:
        "Respuesta correcta. Hemos enviado un código de verificación a tu email.",
      data: {
        tempToken: resetToken,
        email: user.email,
        emailSent,
        expiresIn: "5 minutos",
      },
    });
  } catch (error: any) {
    console.error("❌ Error verificando respuesta de seguridad:", error);
    res.status(500).json({
      success: false,
      error: "Error al verificar respuesta",
    });
  }
};

export const resendRecoveryCode = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { tempToken, method }: Resend2FADTO = req.body;

    // 1. Validar que todos los campos existan
    if (!tempToken || !method) {
      res.status(400).json({
        success: false,
        error: "Token temporal y método son obligatorios",
      });
      return;
    }

    // 2. Validar que el método sea válido
    if (method !== "email") {
      res.status(400).json({
        success: false,
        error: "Método inválido. Solo se permite 'email'",
      });
      return;
    }

    // 3. Verificar token temporal
    const decoded = verifyTemporaryToken(tempToken);

    if (!decoded || decoded.purpose !== "PASSWORD_RESET") {
      res.status(401).json({
        success: false,
        error: "Token temporal inválido o expirado",
      });
      return;
    }

    // 4. Buscar usuario
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    // 5. Verificar si la cuenta está bloqueada
    const blockStatus = await checkIfBlocked(user.id);

    if (blockStatus.isBlocked) {
      const timeLeft = blockStatus.blockedUntil
        ? Math.ceil(
            (blockStatus.blockedUntil.getTime() - Date.now()) / 1000 / 60
          )
        : 10;

      res.status(403).json({
        success: false,
        error: `Cuenta bloqueada temporalmente. Intenta nuevamente en ${timeLeft} minutos.`,
      });
      return;
    }

    // 6. Invalidar código anterior (marcarlo como usado)
    await prisma.verificationCode.updateMany({
      where: {
        userId: user.id,
        type: "PASSWORD_RESET",
        isUsed: false,
      },
      data: { isUsed: true },
    });

    // 7. Generar nuevo código de recuperación
    const newCode = generateVerificationCode();
    const hashedCode = await hashText(newCode);
    const codeExpiration = generateCodeExpiration(5); // 5 minutos

    // 8. Guardar nuevo código en BD
    await prisma.verificationCode.create({
      data: {
        userId: user.id,
        code: hashedCode,
        type: "PASSWORD_RESET",
        expiresAt: codeExpiration,
      },
    });

    // 9. Enviar código por email
    const sent = await sendPasswordResetCode(user.email, newCode);

    if (!sent) {
      console.error(`⚠️  Error enviando código de recuperación por email`);
    }

    console.log(
      `✅ Código de recuperación reenviado por email a: ${user.email}`
    );

    // 10. Responder con éxito
    res.status(200).json({
      success: true,
      message: "Código de recuperación reenviado por email",
      data: {
        method: "email",
        sent,
        expiresIn: "5 minutos",
      },
    });
  } catch (error: any) {
    console.error("❌ Error reenviando código de recuperación:", error);
    res.status(500).json({
      success: false,
      error: "Error al reenviar código",
    });
  }
};

export const verifyRecoveryCode = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { tempToken, code }: VerifyRecoveryCodeDTO = req.body;

    // 1. Validar que todos los campos existan
    if (!tempToken || !code) {
      res.status(400).json({
        success: false,
        error: "Token temporal y código son obligatorios",
      });
      return;
    }

    // 2. Validar formato del código (6 dígitos)
    if (!isValidCode(code)) {
      res.status(400).json({
        success: false,
        error: "El código debe ser de 6 dígitos",
      });
      return;
    }

    // 3. Verificar token temporal
    const decoded = verifyTemporaryToken(tempToken);

    if (!decoded || decoded.purpose !== "PASSWORD_RESET") {
      res.status(401).json({
        success: false,
        error: "Token temporal inválido o expirado",
      });
      return;
    }

    // 4. Buscar usuario
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    // 5. Verificar si la cuenta está bloqueada
    const blockStatus = await checkIfBlocked(user.id);

    if (blockStatus.isBlocked) {
      const timeLeft = blockStatus.blockedUntil
        ? Math.ceil(
            (blockStatus.blockedUntil.getTime() - Date.now()) / 1000 / 60
          )
        : 10;

      res.status(403).json({
        success: false,
        error: `Cuenta bloqueada temporalmente. Intenta nuevamente en ${timeLeft} minutos.`,
      });
      return;
    }

    // 6. Buscar código de recuperación más reciente
    const storedCode = await prisma.verificationCode.findFirst({
      where: {
        userId: user.id,
        type: "PASSWORD_RESET",
        isUsed: false,
      },
      orderBy: { createdAt: "desc" },
    });

    if (!storedCode) {
      res.status(400).json({
        success: false,
        error: "Código no encontrado o ya fue usado",
      });
      return;
    }

    // 7. Verificar si el código expiró
    const now = new Date();
    if (now > storedCode.expiresAt) {
      res.status(400).json({
        success: false,
        error: "El código ha expirado. Solicita uno nuevo.",
      });
      return;
    }

    // 8. Verificar código con bcrypt
    const isCodeValid = await compareHash(code, storedCode.code);

    // 9. Si el código es INCORRECTO ❌
    if (!isCodeValid) {
      // Incrementar intentos fallidos
      const attemptResult = await incrementFailedAttempts(
        user.id,
        user.email,
        "Código de recuperación incorrecto"
      );

      // Registrar intento fallido
      await prisma.loginAttempt.create({
        data: {
          userId: user.id,
          email: user.email,
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"],
          success: false,
          failReason: "Código de recuperación incorrecto",
        },
      });

      securityLogger.logFailedLogin(
        user.email,
        req.ip || "unknown",
        "Código de recuperación incorrecto"
      );

      // Si se bloqueó la cuenta
      if (attemptResult.isBlocked) {
        securityLogger.logAccountBlocked(user.email, req.ip || "unknown");

        res.status(403).json({
          success: false,
          error:
            "Demasiados intentos fallidos. Tu cuenta ha sido bloqueada temporalmente. Se ha enviado un email de alerta.",
          isBlocked: true,
        });
        return;
      }

      // Si aún no se bloquea
      res.status(401).json({
        success: false,
        error: "Código incorrecto",
        attemptsLeft: attemptResult.attemptsLeft,
      });
      return;
    }

    // 10. Si el código es CORRECTO ✅

    // Resetear intentos fallidos
    await resetFailedAttempts(user.id);

    // 11. Marcar código como usado
    await prisma.verificationCode.update({
      where: { id: storedCode.id },
      data: { isUsed: true },
    });

    // 12. Generar token de reset (válido por 10 minutos)
    const resetToken = generateTemporaryToken(
      {
        userId: user.id,
        purpose: "PASSWORD_RESET",
      },
      "10m"
    );

    console.log(
      `✅ Código de recuperación verificado correctamente: ${user.email}`
    );

    // 13. Responder con token de reset
    res.status(200).json({
      success: true,
      message:
        "Código verificado correctamente. Ahora puedes cambiar tu contraseña.",
      data: {
        resetToken,
        expiresIn: "10 minutos",
      },
    });
  } catch (error: any) {
    console.error("❌ Error en verificación de código de recuperación:", error);
    res.status(500).json({
      success: false,
      error: "Error al verificar código",
    });
  }
};

export const resetPassword = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { resetToken, newPassword, confirmPassword }: ResetPasswordDTO =
      req.body;

    // 1. Validar que todos los campos existan
    if (!resetToken || !newPassword || !confirmPassword) {
      res.status(400).json({
        success: false,
        error: "Todos los campos son obligatorios",
      });
      return;
    }

    // 2. Validar que las contraseñas coincidan
    if (newPassword !== confirmPassword) {
      res.status(400).json({
        success: false,
        error: "Las contraseñas no coinciden",
      });
      return;
    }

    // 3. Validar fortaleza de la nueva contraseña
    if (!isValidPassword(newPassword)) {
      res.status(400).json({
        success: false,
        error: getPasswordErrorMessage(),
      });
      return;
    }

    // 4. Verificar token de reset
    const decoded = verifyTemporaryToken(resetToken);

    if (!decoded || decoded.purpose !== "PASSWORD_RESET") {
      res.status(401).json({
        success: false,
        error: "Token de reset inválido o expirado",
      });
      return;
    }

    // 5. Buscar usuario
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
      return;
    }

    // 6. Verificar que la nueva contraseña no sea igual a la anterior
    const isSamePassword = await verifyPassword(newPassword, user.password);

    if (isSamePassword) {
      res.status(400).json({
        success: false,
        error: "La nueva contraseña no puede ser igual a la anterior",
      });
      return;
    }

    // 7. Encriptar nueva contraseña
    const hashedPassword = await hashPassword(newPassword);

    // 8. Actualizar contraseña en BD
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        failedAttempts: 0, // Resetear intentos fallidos
        isBlocked: false, // Desbloquear cuenta si estaba bloqueada
        blockedUntil: null,
      },
    });

    // 9. Invalidar todos los códigos de verificación del usuario
    await prisma.verificationCode.updateMany({
      where: {
        userId: user.id,
        isUsed: false,
      },
      data: { isUsed: true },
    });

    // 10. Enviar email de confirmación de cambio
    const { sendPasswordChangedConfirmation } = await import(
      "../services/emailService"
    );
    const emailSent = await sendPasswordChangedConfirmation(user.email);

    if (!emailSent) {
      console.error("⚠️  Error enviando email de confirmación");
    }

    // 11. Registrar evento de seguridad
    securityLogger.logPasswordReset(user.email);

    // 12. Registrar en LoginAttempt
    await prisma.loginAttempt.create({
      data: {
        userId: user.id,
        email: user.email,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        success: true,
        failReason: "Password reset exitoso",
      },
    });

    console.log(
      `✅ Contraseña cambiada exitosamente: ${maskEmail(user.email)}`
    );

    // 13. Responder con éxito
    res.status(200).json({
      success: true,
      message:
        "Contraseña cambiada exitosamente. Ahora puedes iniciar sesión con tu nueva contraseña.",
      data: {
        email: user.email,
        passwordChanged: true,
      },
    });
  } catch (error: any) {
    console.error("❌ Error en resetPassword:", error);
    res.status(500).json({
      success: false,
      error: "Error al cambiar contraseña",
    });
  }
};

export const verifyResetToken = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { id: resetId } = req.params;

    console.log("🔍 Params recibidos:", req.params); // 👈 AGREGAR ESTO
    console.log("🔍 URL completa:", req.url);

    console.log("🔍 resetId recibido:", resetId);

    // 1. Validar que el resetId exista
    if (!resetId) {
      res.status(400).json({
        success: false,
        error: "ID es obligatorio",
      });
      return;
    }

    // 2. Buscar usuario con ese resetId (NO con resetToken)
    const user = await prisma.user.findFirst({
      where: {
        resetId: resetId, // 👈 Buscar por resetId público
      },
    });

    // 3. Si no existe el usuario o el resetId
    if (!user || !user.resetId || !user.resetToken || !user.resetTokenExpiry) {
      res.status(400).json({
        success: false,
        error: "Enlace inválido o expirado",
        isValid: false,
      });
      return;
    }

    // 4. Verificar si hay bloqueo de recuperación
    if (user.recoveryBlockedUntil && new Date() < user.recoveryBlockedUntil) {
      const timeLeft = Math.ceil(
        (user.recoveryBlockedUntil.getTime() - Date.now()) / 1000 / 60
      );

      res.status(403).json({
        success: false,
        error: `Demasiados intentos de recuperación. Intenta nuevamente en ${timeLeft} minutos.`,
        isBlocked: true,
      });
      return;
    }

    // 5. Verificar si el token expiró (5 minutos)
    const now = new Date();
    if (now > user.resetTokenExpiry) {
      // Limpiar token expirado
      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetToken: null,
          resetId: null, // 👈 Limpiar también resetId
          resetTokenExpiry: null,
        },
      });

      res.status(400).json({
        success: false,
        error: "El enlace ha expirado. Solicita uno nuevo.",
        isValid: false,
      });
      return;
    }

    // 6. Generar token temporal para el siguiente paso (NO exponer resetToken)
    const tempToken = generateTemporaryToken(
      {
        userId: user.id,
        resetId: resetId, // 👈 Incluir resetId para validación
        purpose: "PASSWORD_RESET_LINK",
      },
      "10m" // Válido por 10 minutos
    );

    console.log(`Enlace válido para: ${maskEmail(user.email)}`);

    // 7. Responder con tempToken (NO con resetToken)
    res.status(200).json({
      success: true,
      message: "Enlace válido. Puedes cambiar tu contraseña.",
      data: {
        isValid: true,
        tempToken, // 👈 Token temporal de sesión
        email: user.email,
        expiresAt: user.resetTokenExpiry,
      },
    });
  } catch (error: any) {
    console.error("❌ Error verificando enlace de reset:", error);
    res.status(500).json({
      success: false,
      error: "Error al verificar enlace",
    });
  }
};

//CAMBIAR CONTRASEÑA CON ENLACE
export const resetPasswordWithLink = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const {
      tempToken,
      newPassword,
      confirmPassword,
    }: ResetPasswordWithLinkDTO = req.body;

    // 1. Validar que todos los campos existan
    if (!tempToken || !newPassword || !confirmPassword) {
      res.status(400).json({
        success: false,
        error: "Todos los campos son obligatorios",
      });
      return;
    }

    // 2. Validar que las contraseñas coincidan
    if (newPassword !== confirmPassword) {
      res.status(400).json({
        success: false,
        error: "Las contraseñas no coinciden",
      });
      return;
    }

    // 3. Validar fortaleza de la nueva contraseña
    if (!isValidPassword(newPassword)) {
      res.status(400).json({
        success: false,
        error: getPasswordErrorMessage(),
      });
      return;
    }

    // 4. Verificar tempToken (NO resetToken directamente)
    const decoded = verifyTemporaryToken(tempToken);

    if (!decoded || decoded.purpose !== "PASSWORD_RESET_LINK") {
      res.status(401).json({
        success: false,
        error: "Sesión inválida o expirada",
      });
      return;
    }

    // 5. Buscar usuario y verificar resetId
    const user = await prisma.user.findFirst({
      where: {
        id: decoded.userId,
        resetId: decoded.resetId,
      },
    });

    // 6. Si no existe o resetId no coincide
    if (!user || !user.resetToken || !user.resetTokenExpiry) {
      res.status(400).json({
        success: false,
        error: "Enlace inválido o ya usado",
      });
      return;
    }

    // 7. Verificar si hay bloqueo de recuperación
    if (user.recoveryBlockedUntil && new Date() < user.recoveryBlockedUntil) {
      const timeLeft = Math.ceil(
        (user.recoveryBlockedUntil.getTime() - Date.now()) / 1000 / 60
      );

      res.status(403).json({
        success: false,
        error: `Demasiados intentos de recuperación. Intenta nuevamente en ${timeLeft} minutos.`,
        isBlocked: true,
      });
      return;
    }

    // 8. Verificar si el token expiró
    const now = new Date();
    if (now > user.resetTokenExpiry) {
      // Incrementar intentos fallidos
      const newAttempts = user.recoveryAttempts + 1;

      if (newAttempts >= 3) {
        // Bloquear por 10 minutos
        const blockedUntil = new Date(Date.now() + 10 * 60 * 1000);

        await prisma.user.update({
          where: { id: user.id },
          data: {
            recoveryAttempts: newAttempts,
            recoveryBlockedUntil: blockedUntil,
            resetToken: null,
            resetId: null, // 👈 Limpiar resetId
            resetTokenExpiry: null,
          },
        });

        res.status(403).json({
          success: false,
          error:
            "Demasiados intentos con enlaces expirados. Cuenta bloqueada temporalmente por 10 minutos.",
          isBlocked: true,
        });
        return;
      }

      // Incrementar intentos sin bloquear
      await prisma.user.update({
        where: { id: user.id },
        data: {
          recoveryAttempts: newAttempts,
          resetToken: null,
          resetId: null, // 👈 Limpiar resetId
          resetTokenExpiry: null,
        },
      });

      res.status(400).json({
        success: false,
        error: "El enlace ha expirado. Solicita uno nuevo.",
        attemptsLeft: 3 - newAttempts,
      });
      return;
    }

    // 9. Verificar que la nueva contraseña no sea igual a la anterior
    const isSamePassword = await verifyPassword(newPassword, user.password);

    if (isSamePassword) {
      res.status(400).json({
        success: false,
        error: "La nueva contraseña no puede ser igual a la anterior",
      });
      return;
    }

    // 10. Encriptar nueva contraseña
    const hashedPassword = await hashPassword(newPassword);

    // 11. Actualizar contraseña y limpiar tokens
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetId: null, // 👈 Limpiar resetId
        resetTokenExpiry: null,
        recoveryAttempts: 0,
        recoveryBlockedUntil: null,
        failedAttempts: 0,
        isBlocked: false,
        blockedUntil: null,
      },
    });

    // 12. Invalidar todos los códigos de verificación del usuario
    await prisma.verificationCode.updateMany({
      where: {
        userId: user.id,
        isUsed: false,
      },
      data: { isUsed: true },
    });

    // 13. Enviar email de confirmación
    const { sendPasswordChangedConfirmation } = await import(
      "../services/emailService"
    );
    const emailSent = await sendPasswordChangedConfirmation(user.email);

    if (!emailSent) {
      console.error("⚠️  Error enviando email de confirmación");
    }

    // 14. Registrar evento de seguridad
    securityLogger.logPasswordReset(user.email);

    // 15. Registrar en LoginAttempt
    await prisma.loginAttempt.create({
      data: {
        userId: user.id,
        email: user.email,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        success: true,
        failReason: "Password reset con enlace exitoso",
      },
    });

    console.log(`✅ Contraseña cambiada con enlace: ${maskEmail(user.email)}`);

    // 16. Responder con éxito
    res.status(200).json({
      success: true,
      message:
        "Contraseña cambiada exitosamente. Ahora puedes iniciar sesión con tu nueva contraseña.",
      data: {
        email: user.email,
        passwordChanged: true,
      },
    });
  } catch (error: any) {
    console.error("❌ Error en resetPasswordWithLink:", error);
    res.status(500).json({
      success: false,
      error: "Error al cambiar contraseña",
    });
  }
};
