// Regex para validar email
const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;

// Regex para validar teléfono (formato internacional con +)
const phoneRegex = /^\+[1-9]\d{1,14}$/;

// Regex para validar contraseña fuerte
// Mínimo 8 caracteres, al menos una mayúscula, una minúscula, un número y un carácter especial
const passwordRegex =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#/])[A-Za-z\d@$!%*?&#/]{8,}$/;

// Validar email
export const isValidEmail = (email: string): boolean => {
  return emailRegex.test(email);
};

// Validar teléfono
export const isValidPhone = (phone: string): boolean => {
  return phoneRegex.test(phone);
};

// Validar contraseña
export const isValidPassword = (password: string): boolean => {
  return passwordRegex.test(password);
};

// Validar longitud de nombre
export const isValidName = (name: string): boolean => {
  return name.trim().length >= 2 && name.trim().length <= 100;
};

// Validar código de verificación (6 dígitos)
export const isValidCode = (code: string): boolean => {
  return /^\d{6}$/.test(code);
};

// Función para obtener mensaje de error de contraseña
export const getPasswordErrorMessage = (): string => {
  return "La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial (@$!%*?&#)";
};

// Función para sanitizar entrada (remover espacios extra, convertir a lowercase si es email)
export const sanitizeEmail = (email: string): string => {
  return email.trim().toLowerCase();
};

export const sanitizeName = (name: string): string => {
  return name.trim();
};

export const sanitizePhone = (phone: string): string => {
  return phone.trim();
};

/**
 * Valida que la pregunta de seguridad sea válida
 */
export const isValidSecurityQuestion = (questionId: string): boolean => {
  const validIds = [
    "pet_name",
    "birth_city",
    "mother_maiden",
    "first_school",
    "childhood_friend",
    "first_car",
    "favorite_teacher",
    "first_job",
    "favorite_book",
    "childhood_nickname",
  ];
  return validIds.includes(questionId);
};

/**
 * Valida que la respuesta de seguridad tenga al menos 2 caracteres
 */
export const isValidSecurityAnswer = (answer: string): boolean => {
  if (!answer || typeof answer !== "string") return false;
  const trimmed = answer.trim();
  return trimmed.length >= 2 && trimmed.length <= 100;
};

/**
 * Sanitiza la respuesta de seguridad (trim + lowercase para comparación)
 */
export const sanitizeSecurityAnswer = (answer: string): string => {
  return answer.trim().toLowerCase();
};
