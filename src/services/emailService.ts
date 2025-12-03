import axios from "axios";

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_API_URL = "https://api.brevo.com/v3/smtp/email";
const SENDER_EMAIL = "angelsc1919@gmail.com";
const SENDER_NAME = "Sistema de Autenticación";

interface EmailOptions {
  to: string;
  subject: string;
  htmlContent: string;
}

/**
 * Envía un email usando Brevo
 */
const sendEmail = async ({
  to,
  subject,
  htmlContent,
}: EmailOptions): Promise<boolean> => {
  if (!BREVO_API_KEY) {
    console.error("BREVO_API_KEY no está configurada");
    return false;
  }

  try {
    const response = await axios.post(
      BREVO_API_URL,
      {
        sender: { name: SENDER_NAME, email: SENDER_EMAIL },
        to: [{ email: to }],
        subject,
        htmlContent,
      },
      {
        headers: {
          "api-key": BREVO_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("Email enviado exitosamente");
    return true;
  } catch (error: any) {
    console.error("❌ Error enviando email:", error.message);
    return false;
  }
};

/**
 * Envía código de verificación de registro
 */
export const sendVerificationCode = async (
  email: string,
  code: string
): Promise<boolean> => {
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Código de Verificación</h2>
      <p>Tu código de verificación es:</p>
      <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
        ${code}
      </div>
      <p style="color: #666;">Este código expirará en 5 minutos.</p>
      <p style="color: #999; font-size: 12px;">Si no solicitaste este código, ignora este mensaje.</p>
    </div>
  `;

  return await sendEmail({
    to: email,
    subject: "Código de Verificación - Sistema de Autenticación",
    htmlContent,
  });
};

/**
 * Envía código 2FA para login
 */
export const send2FACode = async (
  email: string,
  code: string
): Promise<boolean> => {
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Código de Autenticación</h2>
      <p>Se ha solicitado acceso a tu cuenta. Tu código de verificación es:</p>
      <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
        ${code}
      </div>
      <p style="color: #666;">Este código expirará en 5 minutos.</p>
      <p style="color: #999; font-size: 12px;">Si no fuiste tú quien intentó iniciar sesión, cambia tu contraseña inmediatamente.</p>
    </div>
  `;

  return await sendEmail({
    to: email,
    subject: "Código 2FA - Sistema de Autenticación",
    htmlContent,
  });
};

/**
 * Envía código de recuperación de contraseña
 */
export const sendPasswordResetCode = async (
  email: string,
  code: string
): Promise<boolean> => {
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Recuperación de Contraseña</h2>
      <p>Has solicitado restablecer tu contraseña. Tu código de verificación es:</p>
      <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
        ${code}
      </div>
      <p style="color: #666;">Este código expirará en 5 minutos.</p>
      <p style="color: #999; font-size: 12px;">Si no solicitaste restablecer tu contraseña, ignora este mensaje.</p>
    </div>
  `;

  return await sendEmail({
    to: email,
    subject: "Recuperación de Contraseña - Sistema de Autenticación",
    htmlContent,
  });
};

/**
 * Envía alerta de cuenta bloqueada
 */
export const sendAccountBlockedAlert = async (
  email: string,
  reason: string
): Promise<boolean> => {
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #d32f2f;">⚠️ Alerta de Seguridad</h2>
      <p>Tu cuenta ha sido bloqueada temporalmente debido a múltiples intentos fallidos.</p>
      <p><strong>Razón:</strong> ${reason}</p>
      <p>Tu cuenta se desbloqueará automáticamente en <strong>10 minutos</strong>.</p>
      <p style="color: #666;">Si no fuiste tú quien intentó acceder, te recomendamos cambiar tu contraseña cuando tu cuenta se desbloquee.</p>
      <p style="color: #999; font-size: 12px;">Este es un mensaje automático de seguridad.</p>
    </div>
  `;

  return await sendEmail({
    to: email,
    subject: "⚠️ Alerta de Seguridad - Cuenta Bloqueada",
    htmlContent,
  });
};

/**
 * Envía confirmación de cambio de contraseña
 */
export const sendPasswordChangedConfirmation = async (
  email: string
): Promise<boolean> => {
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #4caf50;">Contraseña Cambiada</h2>
      <p>Tu contraseña ha sido cambiada exitosamente.</p>
      <p>Si no realizaste este cambio, contacta inmediatamente con soporte.</p>
      <p style="color: #999; font-size: 12px;">Fecha: ${new Date().toLocaleString()}</p>
    </div>
  `;

  return await sendEmail({
    to: email,
    subject: "Contraseña Cambiada - Sistema de Autenticación",
    htmlContent,
  });
};

/**
 * Envía enlace de recuperación de contraseña
 */
export const sendPasswordResetLink = async (
  email: string,
  resetId: string
): Promise<boolean> => {
  const FRONTEND_URL = "https://frontend-actividad-seguridad-binas.vercel.app";
  const resetLink = `${FRONTEND_URL}/reset-password-link?id=${resetId}`;

  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Recuperación de Contraseña</h2>
      <p>Has solicitado restablecer tu contraseña. Haz clic en el siguiente enlace para continuar:</p>
      <div style="margin: 30px 0; text-align: center;">
        <a href="${resetLink}" 
           style="background-color: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
          Restablecer Contraseña
        </a>
      </div>
      <p style="color: #d32f2f; font-weight: bold;">⚠️ Este enlace expirará en 5 minutos.</p>
      <p style="color: #999; font-size: 12px;">Si no solicitaste restablecer tu contraseña, ignora este mensaje.</p>
    </div>
  `;

  return await sendEmail({
    to: email,
    subject: "Enlace de Recuperación de Contraseña - Sistema de Autenticación",
    htmlContent,
  });
};

/**
 * Envía enlace de verificación de email al registrarse
 */
export const sendVerificationLink = async (
  email: string,
  verificationId: string
): Promise<boolean> => {
  const FRONTEND_URL = "https://frontend-actividad-seguridad-binas.vercel.app";
  const verificationLink = `${FRONTEND_URL}/verify-email-link?id=${verificationId}`;

  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Verifica tu correo electrónico</h2>
      <p>Gracias por registrarte. Para activar tu cuenta, haz clic en el siguiente enlace:</p>
      <div style="margin: 30px 0; text-align: center;">
        <a href="${verificationLink}" 
           style="background-color: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
          Verificar Email
        </a>
      </div>
      <p style="color: #d32f2f; font-weight: bold;">⚠️ Este enlace expirará en 5 minutos.</p>
      <p style="color: #999; font-size: 12px;">Si no te registraste en nuestro sitio, ignora este mensaje.</p>
    </div>
  `;

  return await sendEmail({
    to: email,
    subject: "Verifica tu Email - Sistema de Autenticación",
    htmlContent,
  });
};
