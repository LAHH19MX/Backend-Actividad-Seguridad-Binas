import rateLimit from "express-rate-limit";

// Rate limiter general (100 requests por 15 minutos por IP)
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    success: false,
    error:
      "Demasiadas solicitudes desde esta IP. Por favor, intenta más tarde.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiter estricto para autenticación (3 intentos por 15 minutos)
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: {
    success: false,
    error:
      "Demasiados intentos de inicio de sesión. Cuenta bloqueada temporalmente.",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

// Rate limiter para registro (3 registros por hora por IP)
export const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: {
    success: false,
    error: "Demasiados intentos de registro desde esta IP. Intenta más tarde.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiter para envío de códigos (10 por hora)
export const codeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    error: "Demasiadas solicitudes de código. Intenta más tarde.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});
