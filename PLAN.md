# 📋 PLAN COMPLETO - NestJS Auth App

## 🎯 Objetivo
Crear una aplicación NestJS completa que demuestre autenticación con JWT, guards, decoradores, rutas públicas y protegidas.

## 📚 Conceptos que se Aprenderán

### 1. **Fundamentos NestJS**
- CLI de NestJS y generación de recursos
- Módulos, Controladores y Servicios
- Inyección de dependencias
- Pipes y validación

### 2. **Autenticación y Seguridad**
- JWT (JSON Web Tokens)
- Passport.js con NestJS
- Hash de contraseñas con bcrypt
- Estrategias de autenticación

### 3. **Guards (Guardias)**
- Qué son y cómo funcionan
- AuthGuard para proteger rutas
- Guards personalizados
- Orden de ejecución

### 4. **Decoradores**
- Decoradores built-in de NestJS
- Crear decoradores personalizados
- `@Public()` para rutas públicas
- `@GetUser()` para extraer usuario del request

### 5. **Arquitectura**
- Separación de responsabilidades
- DTOs (Data Transfer Objects)
- Entities/Interfaces
- Mejores prácticas

---

## 🗂️ Estructura del Proyecto

```
nestjs-auth/
├── src/
│   ├── auth/
│   │   ├── decorators/
│   │   │   ├── public.decorator.ts
│   │   │   └── get-user.decorator.ts
│   │   ├── guards/
│   │   │   └── jwt-auth.guard.ts
│   │   ├── strategies/
│   │   │   └── jwt.strategy.ts
│   │   ├── dto/
│   │   │   ├── login.dto.ts
│   │   │   └── register.dto.ts
│   │   ├── auth.controller.ts
│   │   ├── auth.service.ts
│   │   └── auth.module.ts
│   ├── users/
│   │   ├── entities/
│   │   │   └── user.entity.ts
│   │   ├── dto/
│   │   │   └── create-user.dto.ts
│   │   ├── users.controller.ts
│   │   ├── users.service.ts
│   │   └── users.module.ts
│   ├── app.controller.ts
│   ├── app.service.ts
│   ├── app.module.ts
│   └── main.ts
├── GUIA-PASO-A-PASO.md
├── PLAN.md
├── README.md
└── package.json
```

---

## 📝 Pasos de Implementación

### FASE 1: Setup Inicial
- [ ] 1.1 - Inicializar proyecto NestJS
- [ ] 1.2 - Instalar dependencias necesarias
- [ ] 1.3 - Configurar variables de entorno

### FASE 2: Módulo Users
- [ ] 2.1 - Generar módulo Users con CLI
- [ ] 2.2 - Crear entity User
- [ ] 2.3 - Crear DTOs para usuarios
- [ ] 2.4 - Implementar UserService (CRUD básico)
- [ ] 2.5 - Implementar UserController

### FASE 3: Módulo Auth
- [ ] 3.1 - Generar módulo Auth con CLI
- [ ] 3.2 - Instalar @nestjs/jwt y @nestjs/passport
- [ ] 3.3 - Crear DTOs de login y registro
- [ ] 3.4 - Implementar AuthService
  - Hash de contraseñas con bcrypt
  - Validación de credenciales
  - Generación de JWT
- [ ] 3.5 - Crear JWT Strategy
- [ ] 3.6 - Implementar AuthController

### FASE 4: Guards y Decoradores
- [ ] 4.1 - Crear JwtAuthGuard
- [ ] 4.2 - Aplicar guard globalmente
- [ ] 4.3 - Crear decorador @Public()
- [ ] 4.4 - Crear decorador @GetUser()
- [ ] 4.5 - Implementar Reflector para metadata

### FASE 5: Rutas de Ejemplo
- [ ] 5.1 - Ruta pública: POST /auth/register
- [ ] 5.2 - Ruta pública: POST /auth/login
- [ ] 5.3 - Ruta protegida: GET /auth/profile
- [ ] 5.4 - Ruta protegida: GET /users
- [ ] 5.5 - Ruta pública: GET / (health check)

### FASE 6: Testing y Documentación
- [ ] 6.1 - Probar todas las rutas con Thunder Client/Postman
- [ ] 6.2 - Verificar guards funcionan correctamente
- [ ] 6.3 - Documentar cada paso en GUIA-PASO-A-PASO.md
- [ ] 6.4 - Crear README.md completo

---

## 🔑 Endpoints Finales

### Públicos (sin autenticación)
```
GET    /                    - Health check
POST   /auth/register       - Registrar nuevo usuario
POST   /auth/login          - Login y obtener JWT
```

### Protegidos (requieren JWT)
```
GET    /auth/profile        - Obtener perfil del usuario autenticado
GET    /users               - Listar todos los usuarios
GET    /users/:id           - Obtener usuario por ID
```

---

## 🧪 Flujo de Testing

1. **Registrar usuario**
   ```bash
   POST /auth/register
   Body: { "email": "test@test.com", "password": "123456", "name": "Test User" }
   ```

2. **Login**
   ```bash
   POST /auth/login
   Body: { "email": "test@test.com", "password": "123456" }
   Response: { "access_token": "eyJhbGc..." }
   ```

3. **Acceder a ruta protegida**
   ```bash
   GET /auth/profile
   Headers: { "Authorization": "Bearer eyJhbGc..." }
   ```

---

## 📦 Dependencias Principales

```json
{
  "@nestjs/common": "^10.0.0",
  "@nestjs/core": "^10.0.0",
  "@nestjs/jwt": "^10.0.0",
  "@nestjs/passport": "^10.0.0",
  "passport": "^0.6.0",
  "passport-jwt": "^4.0.1",
  "bcrypt": "^5.1.1",
  "class-validator": "^0.14.0",
  "class-transformer": "^0.5.1"
}
```

---

## 💡 Conceptos Clave a Explicar

### JWT (JSON Web Token)
- Qué es y cómo funciona
- Estructura: Header.Payload.Signature
- Por qué es stateless
- Dónde se almacena (localStorage vs httpOnly cookies)

### Guards
- Son clases que implementan `CanActivate`
- Se ejecutan antes del handler de la ruta
- Retornan `true` (permite acceso) o `false` (deniega)
- Pueden ser globales, a nivel de controlador o ruta

### Decoradores
- Son funciones que añaden metadata
- `@SetMetadata()` para metadata personalizada
- `createParamDecorator()` para extraer datos del request
- Reflector para leer metadata en guards

### Passport Strategies
- Estrategia define CÓMO autenticar
- `jwt.strategy.ts` valida el token
- `validate()` se ejecuta si el token es válido
- El resultado se añade a `request.user`

---

## 🎓 Orden de Aprendizaje Recomendado

1. Entender la estructura de módulos en NestJS
2. Crear el módulo Users (CRUD simple)
3. Entender qué es JWT y por qué lo usamos
4. Implementar Auth (login/register)
5. Entender qué son los Guards
6. Aplicar JwtAuthGuard globalmente
7. Crear decorador @Public() para excepciones
8. Crear decorador @GetUser() para extraer usuario
9. Probar todo el flujo completo

---

## ✅ Checklist Final

- [ ] La app corre sin errores
- [ ] Puedo registrar un usuario
- [ ] Puedo hacer login y recibir un token
- [ ] Las rutas protegidas rechazan requests sin token
- [ ] Las rutas protegidas aceptan requests con token válido
- [ ] Las rutas públicas funcionan sin token
- [ ] Los decoradores personalizados funcionan
- [ ] El código está bien organizado y comentado
- [ ] La guía paso a paso está completa
- [ ] El README explica cómo ejecutar el proyecto

---

**Estado Actual**: 🚀 Listo para comenzar implementación
