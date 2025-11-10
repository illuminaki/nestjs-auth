# 🔐 NestJS Auth - Guía de Autenticación con JWT

Aplicación de ejemplo para aprender autenticación en NestJS usando JWT, Guards y Decoradores personalizados.

## 📚 ¿Qué aprenderás?

- ✅ Autenticación con JWT (JSON Web Tokens)
- ✅ Guards para proteger rutas
- ✅ Decoradores personalizados (`@Public()`, `@GetUser()`)
- ✅ Validación de datos con class-validator
- ✅ Hash de contraseñas con bcrypt
- ✅ Passport.js con NestJS
- ✅ Uso del CLI de NestJS

## 🚀 Inicio Rápido

### 1. Instalar dependencias
```bash
npm install
```

### 2. Ejecutar la aplicación
```bash
# Modo desarrollo con hot-reload
npm run start:dev

# Modo producción
npm run build
npm run start:prod
```

La aplicación estará disponible en `http://localhost:3000`

## 📖 Documentación

- **[PLAN.md](./PLAN.md)** - Roadmap completo del proyecto
- **[GUIA-PASO-A-PASO.md](./GUIA-PASO-A-PASO.md)** - Tutorial paso a paso para recrear esta app

## 🔌 Endpoints

### Rutas Públicas (sin autenticación)
```
GET    /                    - Health check
POST   /auth/register       - Registrar nuevo usuario
POST   /auth/login          - Login y obtener JWT
```

### Rutas Protegidas (requieren JWT)
```
GET    /auth/profile        - Obtener perfil del usuario autenticado
GET    /users               - Listar todos los usuarios
GET    /users/:id           - Obtener usuario por ID
```

## 🧪 Probar la API

### 1. Registrar un usuario
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@test.com",
    "password": "123456",
    "name": "Test User"
  }'
```

### 2. Hacer login
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@test.com",
    "password": "123456"
  }'
```

Respuesta:
```json
{
  "user": {
    "id": 1,
    "email": "test@test.com",
    "name": "Test User",
    "createdAt": "2024-01-01T00:00:00.000Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 3. Acceder a ruta protegida
```bash
curl -X GET http://localhost:3000/auth/profile \
  -H "Authorization: Bearer TU_TOKEN_AQUI"
```

## 🏗️ Estructura del Proyecto

```
src/
├── auth/
│   ├── decorators/
│   │   ├── public.decorator.ts      # Decorador @Public()
│   │   └── get-user.decorator.ts    # Decorador @GetUser()
│   ├── guards/
│   │   └── jwt-auth.guard.ts        # Guard JWT personalizado
│   ├── strategies/
│   │   └── jwt.strategy.ts          # Estrategia JWT de Passport
│   ├── dto/
│   │   ├── login.dto.ts
│   │   └── register.dto.ts
│   ├── auth.controller.ts
│   ├── auth.service.ts
│   └── auth.module.ts
├── users/
│   ├── entities/
│   │   └── user.entity.ts
│   ├── dto/
│   │   ├── create-user.dto.ts
│   │   └── update-user.dto.ts
│   ├── users.controller.ts
│   ├── users.service.ts
│   └── users.module.ts
├── app.module.ts
└── main.ts
```

## 🔑 Conceptos Clave

### JWT (JSON Web Token)
Los tokens JWT son una forma segura de transmitir información entre partes. En esta app:
- Se generan al hacer login o registro
- Expiran en 24 horas
- Contienen el ID y email del usuario

### Guards
Los Guards determinan si una petición puede proceder o no:
- `JwtAuthGuard` - Verifica que el token JWT sea válido
- Se aplica globalmente a todas las rutas
- Las rutas públicas se marcan con `@Public()`

### Decoradores Personalizados
- `@Public()` - Marca una ruta como pública (sin autenticación)
- `@GetUser()` - Extrae el usuario del request en rutas protegidas

## 📦 Dependencias Principales

```json
{
  "@nestjs/jwt": "^10.0.0",
  "@nestjs/passport": "^10.0.0",
  "passport-jwt": "^4.0.1",
  "bcrypt": "^5.1.1",
  "class-validator": "^0.14.0",
  "class-transformer": "^0.5.1"
}
```

## 🛠️ Comandos del CLI de NestJS Usados

```bash
# Crear proyecto
nest new nestjs-auth

# Generar módulo Users con CRUD
nest generate resource users

# Generar módulo Auth
nest generate module auth
nest generate service auth
nest generate controller auth
```

## 📝 Notas de Seguridad

⚠️ **Esta es una aplicación de ejemplo para aprendizaje**

En producción deberías:
- Usar variables de entorno para el JWT secret
- Implementar refresh tokens
- Usar una base de datos real (no en memoria)
- Implementar rate limiting
- Usar HTTPS
- Implementar CORS apropiadamente

## 📄 Licencia

MIT
