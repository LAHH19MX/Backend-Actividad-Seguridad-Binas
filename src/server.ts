import express, { Application, Request, Response } from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import prisma from "./config/database";
import { errorHandler, notFoundHandler } from "./middlewares/errorHandler";
import { requestLogger } from "./middlewares/logger";
import { generalLimiter } from "./middlewares/rateLimiter";
import authRoutes from "./routes/authRoutes";
import userRoutes from "./routes/userRoutes";

dotenv.config();

const app: Application = express();
const PORT = parseInt(process.env.PORT || "5000", 10);
const isProduction = process.env.NODE_ENV === "production";

app.use(
  cors({
    origin: (origin, callback) => {
      const allowedOrigins = [
        /^https:\/\/frontend-actividad-seguridad-binas.*\.vercel\.app$/,
      ];

      if (!origin) return callback(null, true);

      const isAllowed = allowedOrigins.some((allowed) => {
        if (allowed instanceof RegExp) {
          return allowed.test(origin);
        }
        return allowed === origin;
      });

      if (isAllowed) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
  })
);

// Middlewares de seguridad
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: {
      action: "deny",
    },
  })
);
app.use(generalLimiter);

// Middlewares de parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// Logging
if (!isProduction) {
  app.use(morgan("dev"));
}

app.use(requestLogger);

// Rutas de prueba
app.get("/api/health", (req: Request, res: Response) => {
  res.json({
    success: true,
    message: "Backend funcionando correctamente",
    timestamp: new Date(),
    environment: process.env.NODE_ENV || "development",
  });
});

app.get("/api/test-db", async (req: Request, res: Response) => {
  try {
    const usersCount = await prisma.user.count();
    const admin = await prisma.user.findUnique({
      where: { email: "admin@sistema.com" },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isVerified: true,
        createdAt: true,
      },
    });

    res.json({
      success: true,
      message: "Conexión a BD exitosa",
      database: "PostgreSQL",
      usersCount,
      admin,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Error conectando a BD",
    });
  }
});

// Rutas de la API
app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

// Iniciar servidor - CAMBIO PRINCIPAL AQUÍ
const HOST = isProduction ? "0.0.0.0" : "localhost";

const server = app.listen(PORT, HOST, () => {
  console.log("=================================");
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`📊 Ambiente: ${process.env.NODE_ENV || "development"}`);
  console.log(`🗄️  Base de datos: Railway PostgreSQL`);
  console.log(`🔒 Seguridad: Helmet + Rate Limiting activados`);
  console.log("=================================");
  if (!isProduction) {
    console.log("Rutas disponibles:");
    console.log(`  GET  http://localhost:${PORT}/api/health`);
    console.log(`  GET  http://localhost:${PORT}/api/test-db`);
    console.log(`  POST http://localhost:${PORT}/api/auth/register`);
    console.log("=================================");
  }
});

// Manejo de errores del servidor
server.on("error", (error: NodeJS.ErrnoException) => {
  if (error.code === "EADDRINUSE") {
    console.error(`❌ Error: Puerto ${PORT} ya está en uso`);
  } else {
    console.error("❌ Error del servidor:", error);
  }
  process.exit(1);
});

// Manejo de cierre graceful
process.on("SIGINT", async () => {
  console.log("\n👋 SIGINT recibido. Cerrando servidor...");
  server.close(async () => {
    await prisma.$disconnect();
    console.log("✅ Servidor cerrado correctamente");
    process.exit(0);
  });
});

process.on("SIGTERM", async () => {
  console.log("\n👋 SIGTERM recibido. Cerrando servidor...");
  server.close(async () => {
    await prisma.$disconnect();
    console.log("✅ Servidor cerrado correctamente");
    process.exit(0);
  });
});
