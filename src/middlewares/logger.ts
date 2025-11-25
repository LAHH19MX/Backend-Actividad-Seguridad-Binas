import { Request, Response, NextFunction } from "express";

// Función para ofuscar emails en logs
const maskEmail = (email: string): string => {
  const [local, domain] = email.split("@");
  if (!local || !domain) return "***@***.***";

  const maskedLocal =
    local.length > 2 ? `${local[0]}***${local[local.length - 1]}` : "***";

  return `${maskedLocal}@${domain}`;
};

// Logger personalizado para requests
export const requestLogger = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const start = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - start;
    const statusColor = res.statusCode >= 400 ? "🔴" : "✅";

    console.log(
      `${statusColor} ${req.method} ${req.path} - Status: ${res.statusCode} - ${duration}ms - IP: ${req.ip}`
    );
  });

  next();
};

// Logger para eventos de seguridad
export const securityLogger = {
  logFailedLogin: (email: string, ip: string, reason: string) => {
    console.warn("Login Fallido:", {
      email: maskEmail(email),
      ip,
      reason,
      timestamp: new Date().toISOString(),
    });
  },

  logAccountBlocked: (email: string, ip: string) => {
    console.error("Cuenta Bloqueada:", {
      email: maskEmail(email),
      ip,
      timestamp: new Date().toISOString(),
    });
  },

  logSuccessfulLogin: (email: string, ip: string) => {
    console.log("Login Exitoso:", {
      email: maskEmail(email),
      ip,
      timestamp: new Date().toISOString(),
    });
  },

  logPasswordReset: (email: string) => {
    console.log("Restablece Contraseña:", {
      email: maskEmail(email),
      timestamp: new Date().toISOString(),
    });
  },
};
