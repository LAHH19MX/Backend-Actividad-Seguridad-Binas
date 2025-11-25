import twilio from "twilio";

const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

let twilioClient: twilio.Twilio | null = null;

// Inicializar cliente de Twilio
if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
  twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
}

/**
 * Envía un SMS usando Twilio
 */
const sendSMS = async (to: string, message: string): Promise<boolean> => {
  if (!twilioClient || !TWILIO_PHONE_NUMBER) {
    console.error("Twilio no está configurado correctamente");
    return false;
  }

  try {
    const result = await twilioClient.messages.create({
      body: message,
      from: TWILIO_PHONE_NUMBER,
      to,
    });

    console.log("✅ SMS enviado exitosamente a:", to, "- SID:", result.sid);
    return true;
  } catch (error: any) {
    console.error("❌ Error enviando SMS:", error.message);
    return false;
  }
};

/**
 * Envía código de verificación de registro por SMS
 */
export const sendVerificationCodeSMS = async (
  phone: string,
  code: string
): Promise<boolean> => {
  const message = `Tu código de verificación es: ${code}. Expira en 5 minutos.`;
  return await sendSMS(phone, message);
};

/**
 * Envía código 2FA por SMS
 */
export const send2FACodeSMS = async (
  phone: string,
  code: string
): Promise<boolean> => {
  const message = `Tu código 2FA es: ${code}. Expira en 5 minutos. Si no fuiste tú, ignora este mensaje.`;
  return await sendSMS(phone, message);
};

/**
 * Envía código de recuperación de contraseña por SMS
 */
export const sendPasswordResetCodeSMS = async (
  phone: string,
  code: string
): Promise<boolean> => {
  const message = `Tu código de recuperación de contraseña es: ${code}. Expira en 5 minutos.`;
  return await sendSMS(phone, message);
};
