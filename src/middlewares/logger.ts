import { Request, Response, NextFunction } from "express";

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
    console.warn("⚠️  FAILED LOGIN:", {
      email,
      ip,
      reason,
      timestamp: new Date().toISOString(),
    });
  },

  logAccountBlocked: (email: string, ip: string) => {
    console.error("🚫 ACCOUNT BLOCKED:", {
      email,
      ip,
      timestamp: new Date().toISOString(),
    });
  },

  logSuccessfulLogin: (email: string, ip: string) => {
    console.log("✅ SUCCESSFUL LOGIN:", {
      email,
      ip,
      timestamp: new Date().toISOString(),
    });
  },

  logPasswordReset: (email: string) => {
    console.log("🔑 PASSWORD RESET:", {
      email,
      timestamp: new Date().toISOString(),
    });
  },
};
