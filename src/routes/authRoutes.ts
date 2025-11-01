import { Router } from "express";
import {
  register,
  verifyRegistration,
  login,
  resend2FA,
  verify2FA,
  forgotPassword,
} from "../controllers/authController";
import {
  registerLimiter,
  codeLimiter,
  authLimiter,
} from "../middlewares/rateLimiter";

const router = Router();

/**
 * @route   POST /api/auth/register
 * @desc    Registrar nuevo usuario
 * @access  Public
 */
router.post("/register", registerLimiter, register);

/**
 * @route   POST /api/auth/verify-registration
 * @desc    Verificar códigos de registro (email + SMS)
 * @access  Public
 */
router.post("/verify-registration", codeLimiter, verifyRegistration);

/**
 * @route   POST /api/auth/login
 * @desc    Iniciar sesión (Parte 1: validar credenciales y enviar 2FA)
 * @access  Public
 */
router.post("/login", authLimiter, login);

/**
 * @route   POST /api/auth/resend-2fa
 * @desc    Reenviar código 2FA por email o SMS
 * @access  Public
 */
router.post("/resend-2fa", codeLimiter, resend2FA);

/**
 * @route   POST /api/auth/verify-2fa
 * @desc    Verificar código 2FA y completar login (genera JWT)
 * @access  Public
 */
router.post("/verify-2fa", codeLimiter, verify2FA);

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Solicitar código de recuperación de contraseña
 * @access  Public
 */
router.post("/forgot-password", codeLimiter, forgotPassword);

// Próximos endpoints (Pasos 12-14):
// router.post('/resend-recovery-code', codeLimiter, resendRecoveryCode);
// router.post('/verify-recovery-code', codeLimiter, verifyRecoveryCode);
// router.post('/reset-password', resetPassword);
// router.post('/logout', logout);
// router.post('/refresh-token', refreshToken);

export default router;
