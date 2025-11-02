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
const PORT = process.env.PORT || 5000;

// Middlewares de seguridad
app.use(helmet());
app.use(generalLimiter);

// Middlewares de parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// CORS
app.use(
  cors({
    origin:
      process.env.FRONTEND_URL ||
      "https://frontend-actividad-seguridad-binas.vercel.app/",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Logging
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}
app.use(requestLogger);

// Rutas de prueba
app.get("/api/health", (req: Request, res: Response) => {
  res.json({
    success: true,
    message: "Backend funcionando correctamente ✅",
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
      message: "Conexión a BD exitosa ✅",
      database: "PostgreSQL (Railway)",
      usersCount,
      admin,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Error conectando a BD ❌",
    });
  }
});

// Rutas de la API
app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes);
app.use("/api/auth", userRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

// Iniciar servidor
app.listen(PORT, () => {
  console.log("=================================");
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
  console.log(`📊 Ambiente: ${process.env.NODE_ENV || "development"}`);
  console.log(`🗄️  Base de datos: Railway PostgreSQL`);
  console.log(`🔒 Seguridad: Helmet + Rate Limiting activados`);
  console.log("=================================");
  console.log("Rutas disponibles:");
  console.log(`  GET  http://localhost:${PORT}/api/health`);
  console.log(`  GET  http://localhost:${PORT}/api/test-db`);
  console.log(`  POST http://localhost:${PORT}/api/auth/register`);
  console.log("=================================");
});

// Manejo de cierre graceful
process.on("SIGINT", async () => {
  console.log("\n⚠️  Cerrando servidor...");
  await prisma.$disconnect();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("\n⚠️  Cerrando servidor...");
  await prisma.$disconnect();
  process.exit(0);
});
