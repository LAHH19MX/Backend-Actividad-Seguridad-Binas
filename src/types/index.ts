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
  method: "email";
}

export interface ForgotPasswordDTO {
  email: string;
  method?: "code" | "link";
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

// NUEVO: DTO para reset con enlace
export interface ResetPasswordWithLinkDTO {
  tempToken: string;
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

export interface RegisterWithSecurityDTO extends RegisterDTO {
  securityQuestion: string;
  securityAnswer: string;
}

// DTO para iniciar recuperación con pregunta secreta
export interface ForgotPasswordSecurityDTO {
  email: string;
  method: "security_question";
}

// DTO para verificar respuesta de pregunta secreta
export interface VerifySecurityAnswerDTO {
  tempToken: string;
  answer: string;
}

export const SECURITY_QUESTIONS = [
  { id: "pet_name", question: "¿Cuál es el nombre de tu primera mascota?" },
  { id: "birth_city", question: "¿En qué ciudad naciste?" },
  {
    id: "mother_maiden",
    question: "¿Cuál es tu color favorito?",
  },
  {
    id: "first_school",
    question: "¿Cuál fue el nombre de tu primera escuela?",
  },
  {
    id: "childhood_friend",
    question: "¿Cómo se llamaba tu mejor amigo/a de la infancia?",
  },
  { id: "first_car", question: "¿Cuál fue la marca de tu primer auto?" },
  {
    id: "favorite_teacher",
    question: "¿Cómo se llamaba tu maestro/a favorito/a?",
  },
  { id: "first_job", question: "¿Cuál fue tu primer trabajo?" },
  { id: "favorite_book", question: "¿Cuál es el título de tu libro favorito?" },
  { id: "childhood_nickname", question: "¿Cuál era tu apodo en la infancia?" },
] as const;

export type SecurityQuestionId = (typeof SECURITY_QUESTIONS)[number]["id"];
