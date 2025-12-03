import { Router } from "express";
import {
  getProfile,
  logout,
  refreshToken,
  logoutAll,
} from "../controllers/userController";
import {
  authenticate,
  requireAdmin,
  requireCliente,
} from "../middlewares/authMiddleware";

const router = Router();

/**
 * @route   GET /api/user/profile
 * @desc    Obtener perfil del usuario autenticado
 * @access  Private (requiere JWT válido)
 */
router.get("/profile", authenticate, getProfile);

/**
 * @route   POST /api/auth/logout
 * @desc    Cerrar sesión
 * @access  Private (requiere JWT válido)
 */
router.post("/logout", authenticate, logout);

/**
 * @route   POST /api/user/logout-all
 * @desc    Cerrar sesión en todos los dispositivos
 * @access  Private (requiere JWT válido)
 */
router.post("/logout-all", authenticate, logoutAll);

/**
 * @route   POST /api/auth/refresh-token
 * @desc    Refrescar token JWT
 * @access  Private (requiere JWT válido)
 */
router.post("/refresh-token", authenticate, refreshToken);

// Ejemplo de ruta solo para ADMIN
/**
 * @route   GET /api/user/admin-only
 * @desc    Ruta de ejemplo solo para administradores
 * @access  Private (requiere JWT + rol ADMIN)
 */
router.get("/admin-only", authenticate, requireAdmin, (req, res) => {
  res.json({
    success: true,
    message: "Acceso autorizado: Eres administrador",
    data: {
      role: "ADMIN",
    },
  });
});

// Ejemplo de ruta solo para CLIENTE
/**
 * @route   GET /api/user/client-only
 * @desc    Ruta de ejemplo solo para clientes
 * @access  Private (requiere JWT + rol CLIENTE)
 */
router.get("/client-only", authenticate, requireCliente, (req, res) => {
  res.json({
    success: true,
    message: "Acceso autorizado: Eres cliente",
    data: {
      role: "CLIENTE",
    },
  });
});

export default router;
