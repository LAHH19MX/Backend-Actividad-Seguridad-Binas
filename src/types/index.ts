import { Request } from "express";

// Tipo extendido de Request para incluir user autenticado
export interface AuthRequest extends Request {
  user?: {
    userId: string;
    email: string;
    role: string;
  };
}

// DTOs (Data Transfer Objects)
export interface RegisterDTO {
  name: string;
  email: string;
  phone: string;
  password: string;
  confirmPassword: string;
}

export interface VerifyRegistrationDTO {
  email: string;
  emailCode: string;
  smsCode: string;
}

export interface LoginDTO {
  email: string;
  password: string;
}

export interface Verify2FADTO {
  tempToken: string;
  code: string;
}

export interface Resend2FADTO {
  tempToken: string;
  method: "email" | "sms";
}

export interface ForgotPasswordDTO {
  email: string;
}

export interface VerifyRecoveryCodeDTO {
  tempToken: string;
  code: string;
}

export interface ResetPasswordDTO {
  resetToken: string;
  newPassword: string;
  confirmPassword: string;
}

// Response types
export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
}
