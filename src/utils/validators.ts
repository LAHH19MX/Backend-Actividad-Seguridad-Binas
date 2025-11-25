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
