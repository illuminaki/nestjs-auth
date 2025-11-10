# GUÍA PASO A PASO - NestJS Auth con JWT

Esta guía te llevará paso a paso para crear una aplicación NestJS completa con autenticación JWT, guards y decoradores personalizados.

---

# FUNDAMENTOS TEÓRICOS

## ¿Qué es JWT (JSON Web Token)?

JWT es un estándar abierto (RFC 7519) que define una forma compacta y autónoma de transmitir información de manera segura entre partes como un objeto JSON. Esta información puede ser verificada y confiable porque está firmada digitalmente.

### Estructura de un JWT

Un JWT consta de tres partes separadas por puntos (.):

```
xxxxx.yyyyy.zzzzz
```

**1. Header (Encabezado)**
Contiene el tipo de token (JWT) y el algoritmo de firma utilizado (HS256, RS256, etc.)

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**2. Payload (Carga útil)**
Contiene las "claims" (declaraciones) sobre la entidad (generalmente el usuario) y metadatos adicionales.

```json
{
  "sub": "1234567890",
  "email": "usuario@example.com",
  "iat": 1516239022,
  "exp": 1516242622
}
```

**Claims estándar:**
- `sub` (subject): Identificador del sujeto del token
- `iat` (issued at): Timestamp de cuando se creó el token
- `exp` (expiration): Timestamp de cuando expira el token
- `iss` (issuer): Emisor del token
- `aud` (audience): Audiencia del token

**3. Signature (Firma)**
Se crea tomando el header codificado, el payload codificado, una clave secreta y el algoritmo especificado en el header.

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### ¿Cómo funciona JWT en autenticación?

**Flujo de autenticación:**

1. **Login:** El usuario envía credenciales (email/password) al servidor
2. **Validación:** El servidor verifica las credenciales contra la base de datos
3. **Generación:** Si son válidas, el servidor genera un JWT firmado
4. **Respuesta:** El servidor envía el JWT al cliente
5. **Almacenamiento:** El cliente guarda el JWT (localStorage, sessionStorage, cookie)
6. **Peticiones:** En cada petición, el cliente envía el JWT en el header Authorization
7. **Verificación:** El servidor verifica la firma del JWT
8. **Acceso:** Si es válido, el servidor procesa la petición

```
Cliente                                    Servidor
   |                                          |
   |  POST /auth/login                        |
   |  { email, password }                     |
   |----------------------------------------->|
   |                                          | Verifica credenciales
   |                                          | Genera JWT
   |  { access_token: "xxx.yyy.zzz" }         |
   |<-----------------------------------------|
   |                                          |
   | Guarda el token                          |
   |                                          |
   |  GET /auth/profile                       |
   |  Authorization: Bearer xxx.yyy.zzz       |
   |----------------------------------------->|
   |                                          | Verifica firma del JWT
   |                                          | Extrae información del payload
   |  { user: {...} }                         |
   |<-----------------------------------------|
```

### Ventajas de JWT

**1. Stateless (Sin estado)**
- El servidor no necesita almacenar sesiones
- Toda la información está en el token
- Fácil de escalar horizontalmente

**2. Portabilidad**
- Funciona en cualquier plataforma (web, móvil, IoT)
- Se puede usar entre diferentes dominios
- Compatible con arquitecturas de microservicios

**3. Seguridad**
- Firmado digitalmente (no puede ser alterado)
- Puede ser encriptado para mayor seguridad
- Expira automáticamente

**4. Performance**
- No requiere consultas a base de datos para validar
- Verificación rápida mediante firma criptográfica
- Reduce carga en el servidor

### Desventajas de JWT

**1. No se puede invalidar antes de expirar**
- Una vez emitido, es válido hasta su expiración
- Solución: Usar tokens de corta duración + refresh tokens
- Alternativa: Mantener una lista negra de tokens (pierde el beneficio stateless)

**2. Tamaño**
- Más grande que un session ID tradicional
- Se envía en cada petición
- Puede afectar el ancho de banda

**3. Información expuesta**
- El payload es decodificable (Base64)
- No almacenar información sensible
- Solo información pública o identificadores

### Mejores prácticas de seguridad

**1. Usar HTTPS**
- Siempre transmitir tokens sobre conexiones seguras
- Previene ataques de man-in-the-middle

**2. Tiempo de expiración corto**
- Access tokens: 15 minutos - 1 hora
- Refresh tokens: 7 días - 30 días

**3. Almacenamiento seguro**
- Preferir httpOnly cookies sobre localStorage
- Proteger contra XSS (Cross-Site Scripting)
- Implementar CSRF protection si se usan cookies

**4. Validar siempre**
- Verificar la firma en cada petición
- Validar el tiempo de expiración
- Verificar los claims (issuer, audience)

**5. No almacenar información sensible**
- Solo IDs y datos públicos en el payload
- Nunca contraseñas o información confidencial
- Recordar que el payload es decodificable

### JWT vs Sesiones tradicionales

| Aspecto | JWT | Sesiones |
|---------|-----|----------|
| Almacenamiento servidor | No requiere | Requiere (memoria/Redis/DB) |
| Escalabilidad | Excelente | Requiere sticky sessions |
| Invalidación | Difícil | Inmediata |
| Tamaño | Mayor (~200-500 bytes) | Menor (~32 bytes session ID) |
| Stateless | Sí | No |
| Microservicios | Ideal | Complejo |
| Overhead red | Mayor | Menor |

### ¿Cuándo usar JWT?

**Casos ideales:**
- APIs RESTful stateless
- Aplicaciones móviles
- Single Page Applications (SPA)
- Arquitecturas de microservicios
- Autenticación entre dominios
- Sistemas distribuidos

**Casos donde considerar alternativas:**
- Aplicaciones web tradicionales con sesiones
- Cuando se requiere invalidación inmediata
- Sistemas con requisitos de seguridad muy estrictos
- Aplicaciones con ancho de banda limitado

---

## Requisitos Previos

Antes de comenzar, asegúrate de tener instalado:
- Node.js (v18 o superior)
- npm o yarn
- Un editor de código (VS Code recomendado)
- Conocimientos básicos de TypeScript y Node.js

---

## ¿Qué vamos a construir?

Una API REST con:
- Sistema de registro y login
- Autenticación con JWT
- Rutas públicas y protegidas
- Guards personalizados
- Decoradores personalizados
- Validación de datos
- Hash de contraseñas

---

# FASE 1: SETUP INICIAL

## Paso 1: Instalar el CLI de NestJS

El CLI de NestJS nos ayudará a generar código y estructurar el proyecto correctamente.

```bash
npm install -g @nestjs/cli
```

Por qué: El CLI de NestJS automatiza la creación de módulos, controladores, servicios y más, siguiendo las mejores prácticas.

**Verificar instalación:**
```bash
nest --version
```

---

## Paso 2: Crear el Proyecto

Ahora vamos a crear nuestro proyecto NestJS desde cero.

```bash
# Si estás en una carpeta vacía:
nest new . --package-manager npm --skip-git

# Si quieres crear una nueva carpeta:
nest new nestjs-auth --package-manager npm
cd nestjs-auth
```

Qué hace este comando:
- Crea la estructura base del proyecto
- Instala todas las dependencias necesarias
- Configura TypeScript
- Crea archivos de configuración (tsconfig, eslint, etc.)

**Estructura creada:**
```
nestjs-auth/
├── src/
│   ├── app.controller.ts
│   ├── app.module.ts
│   ├── app.service.ts
│   └── main.ts
├── test/
├── package.json
├── tsconfig.json
└── nest-cli.json
```

---

## Paso 3: Instalar Dependencias para Autenticación

Necesitamos instalar las librerías para JWT, Passport y validación.

```bash
npm install @nestjs/jwt @nestjs/passport passport passport-jwt bcrypt class-validator class-transformer
```

**Dependencias de desarrollo (tipos de TypeScript):**
```bash
npm install -D @types/passport-jwt @types/bcrypt
```

Qué hace cada paquete:

| Paquete | Propósito |
|---------|-----------|
| `@nestjs/jwt` | Módulo de NestJS para trabajar con JWT |
| `@nestjs/passport` | Integración de Passport.js con NestJS |
| `passport` | Librería de autenticación para Node.js |
| `passport-jwt` | Estrategia JWT para Passport |
| `bcrypt` | Para hashear contraseñas de forma segura |
| `class-validator` | Validación de DTOs con decoradores |
| `class-transformer` | Transformación de objetos planos a clases |

---

## Paso 4: Verificar que el Proyecto Funciona

Antes de continuar, vamos a verificar que todo está bien instalado.

```bash
npm run start:dev
```

Qué hace este comando:
- Compila el código TypeScript
- Inicia el servidor en modo desarrollo
- Habilita hot-reload (recarga automática al hacer cambios)

Deberías ver:
```
[Nest] 12345  - LOG [NestFactory] Starting Nest application...
[Nest] 12345  - LOG [InstanceLoader] AppModule dependencies initialized
[Nest] 12345  - LOG [NestApplication] Nest application successfully started
```

**Probar en el navegador:**
Abre `http://localhost:3000` y deberías ver: `Hello World!`

**O con curl:**
```bash
curl http://localhost:3000
# Respuesta: Hello World!
```

Perfecto! El proyecto base está funcionando.

---

# FASE 2: MÓDULO USERS

## Paso 5: Generar el Módulo Users

Vamos a usar el CLI de NestJS para generar un módulo completo de usuarios con CRUD.

```bash
nest generate resource users
```

El CLI te preguntará:

1. ¿Qué capa de transporte usas? → Selecciona `REST API`
2. ¿Generar puntos de entrada CRUD? → Selecciona `Yes`

Qué genera este comando:
```
CREATE src/users/users.controller.ts
CREATE src/users/users.module.ts
CREATE src/users/users.service.ts
CREATE src/users/dto/create-user.dto.ts
CREATE src/users/dto/update-user.dto.ts
CREATE src/users/entities/user.entity.ts
UPDATE src/app.module.ts
```

Por qué usar el CLI:
- Genera código siguiendo las convenciones de NestJS
- Crea la estructura de carpetas correcta
- Actualiza automáticamente el módulo principal
- Ahorra tiempo y evita errores

---

## Paso 6: Definir la Entidad User

Abre `src/users/entities/user.entity.ts` y reemplaza el contenido:

```typescript
export class User {
  id: number;
  email: string;
  password: string;
  name: string;
  createdAt: Date;
}
```

Qué es una Entity:
Una Entity representa la estructura de datos de nuestro modelo. En este caso, un usuario tiene:
- `id`: Identificador único
- `email`: Correo electrónico (será único)
- `password`: Contraseña hasheada
- `name`: Nombre del usuario
- `createdAt`: Fecha de creación

**Nota:** En producción usarías una base de datos real (TypeORM, Prisma, etc.), pero para aprender usaremos almacenamiento en memoria.

---

## Paso 7: Crear el DTO de Creación de Usuario

Los DTOs (Data Transfer Objects) definen cómo deben verse los datos que llegan a nuestra API.

Abre `src/users/dto/create-user.dto.ts`:

```typescript
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class CreateUserDto {
  @IsEmail({}, { message: 'El email debe ser válido' })
  @IsNotEmpty({ message: 'El email es requerido' })
  email: string;

  @IsString({ message: 'La contraseña debe ser un string' })
  @MinLength(6, { message: 'La contraseña debe tener al menos 6 caracteres' })
  @IsNotEmpty({ message: 'La contraseña es requerida' })
  password: string;

  @IsString({ message: 'El nombre debe ser un string' })
  @IsNotEmpty({ message: 'El nombre es requerido' })
  name: string;
}
```

Qué hacen estos decoradores:

| Decorador | Función |
|-----------|---------|
| `@IsEmail()` | Valida que sea un email válido |
| `@IsString()` | Valida que sea un string |
| `@IsNotEmpty()` | Valida que no esté vacío |
| `@MinLength(6)` | Valida longitud mínima |

Beneficio: Si alguien envía datos inválidos, NestJS automáticamente rechazará la petición con un mensaje de error claro.

---

## Paso 8: Implementar el Users Service

El Service contiene la lógica de negocio. Aquí manejaremos usuarios en memoria.

### Teoría: ¿Qué es un Service en NestJS?

Un **Service** es una clase que contiene la lógica de negocio de la aplicación. Sigue el patrón de diseño de **Separación de Responsabilidades**:

- **Controller**: Maneja las peticiones HTTP y las respuestas
- **Service**: Contiene la lógica de negocio y acceso a datos
- **Entity**: Define la estructura de los datos

**Ventajas de usar Services:**
1. **Reutilización**: La misma lógica puede ser usada por múltiples controladores
2. **Testabilidad**: Es más fácil hacer pruebas unitarias
3. **Mantenibilidad**: El código está organizado y es más fácil de mantener
4. **Inyección de dependencias**: NestJS gestiona automáticamente las instancias

**El decorador @Injectable():**
- Marca la clase como un "provider" que puede ser inyectado
- Permite que NestJS gestione el ciclo de vida de la clase
- Habilita la inyección de dependencias en el constructor

Abre `src/users/users.service.ts` y reemplaza todo el contenido:

```typescript
import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';

/**
 * @Injectable() - Decorador que marca esta clase como un provider
 * Permite que NestJS la inyecte en otros componentes
 */
@Injectable()
export class UsersService {
  /**
   * Simulamos una base de datos en memoria
   * En producción, esto sería reemplazado por una conexión a DB real
   * private: Solo accesible dentro de esta clase
   */
  private users: User[] = [];
  
  /**
   * Contador para generar IDs únicos
   * En una DB real, esto lo manejaría el motor de base de datos
   */
  private currentId = 1;

  /**
   * Crea un nuevo usuario en el sistema
   * @param createUserDto - Datos del usuario a crear (validados por class-validator)
   * @returns Promise<User> - El usuario creado (sin la contraseña)
   */
  async create(createUserDto: CreateUserDto): Promise<User> {
    // 1. Verificar si el email ya existe para evitar duplicados
    // find() busca el primer elemento que cumpla la condición
    const existingUser = this.users.find(u => u.email === createUserDto.email);
    
    if (existingUser) {
      // ConflictException genera un error HTTP 409
      // Indica que hay un conflicto con el estado actual del recurso
      throw new ConflictException('El email ya está registrado');
    }

    // 2. Hashear la contraseña usando bcrypt
    // El segundo parámetro (10) es el "salt rounds" o factor de costo
    // Más rounds = más seguro pero más lento (10 es un buen balance)
    // bcrypt genera automáticamente un "salt" único para cada contraseña
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    // 3. Crear el objeto del nuevo usuario
    // Usamos el operador ++ para incrementar y asignar el ID
    const newUser: User = {
      id: this.currentId++,        // ID auto-incrementado
      email: createUserDto.email,
      password: hashedPassword,     // Guardamos el hash, NO la contraseña original
      name: createUserDto.name,
      createdAt: new Date(),        // Timestamp de creación
    };

    // 4. Agregar el usuario al array (simula INSERT en DB)
    this.users.push(newUser);
    
    // 5. Retornar el usuario creado
    return newUser;
  }

  /**
   * Obtiene todos los usuarios del sistema
   * @returns User[] - Array de usuarios sin contraseñas
   */
  findAll(): User[] {
    // Usamos map() para transformar cada usuario
    // Destructuring: { password, ...user } separa password del resto
    // ...user (spread operator) crea un nuevo objeto con todas las propiedades excepto password
    // Esto es crucial para la seguridad: NUNCA exponer contraseñas
    return this.users.map(({ password, ...user }) => user as User);
  }

  /**
   * Busca un usuario por su ID
   * @param id - ID del usuario a buscar
   * @returns User - Usuario encontrado (sin contraseña)
   * @throws NotFoundException si el usuario no existe
   */
  findOne(id: number): User {
    const user = this.users.find(u => u.id === id);
    
    if (!user) {
      // NotFoundException genera un error HTTP 404
      // Indica que el recurso solicitado no existe
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }
    
    // Destructuring para remover la contraseña antes de retornar
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword as User;
  }

  /**
   * Busca un usuario por email (usado internamente para autenticación)
   * @param email - Email del usuario
   * @returns User | undefined - Usuario completo CON contraseña o undefined
   * NOTA: Este método SÍ retorna la contraseña porque se usa para validar login
   */
  findByEmail(email: string): User | undefined {
    return this.users.find(u => u.email === email);
  }

  update(id: number, updateUserDto: UpdateUserDto): User {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    this.users[userIndex] = { ...this.users[userIndex], ...updateUserDto };
    const { password, ...userWithoutPassword } = this.users[userIndex];
    return userWithoutPassword as User;
  }

  remove(id: number): void {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    this.users.splice(userIndex, 1);
  }
}
```

**Conceptos importantes:**

1. **Hash de contraseñas con bcrypt:**
   ```typescript
   const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
   ```
   - Nunca guardamos contraseñas en texto plano
   - El número `10` es el "salt rounds" (complejidad del hash)

2. **Manejo de errores:**
   - `ConflictException`: Email duplicado (409)
   - `NotFoundException`: Usuario no encontrado (404)

3. **Seguridad:**
   - Siempre removemos la contraseña antes de retornar usuarios
   - Usamos destructuring: `const { password, ...user } = fullUser`

---

## Paso 9: Exportar el Users Service

Para que otros módulos puedan usar `UsersService`, debemos exportarlo.

Abre `src/users/users.module.ts` y agrega `exports`:

```typescript
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

@Module({
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService], // ← AGREGAR ESTA LÍNEA
})
export class UsersModule {}
```

¿Por qué exportar?
El módulo `AuthModule` necesitará acceder a `UsersService` para buscar usuarios por email durante el login.

---

# FASE 3: MÓDULO AUTH

## Paso 10: Generar el Módulo Auth

Ahora vamos a crear el módulo de autenticación.

```bash
nest generate module auth
nest generate service auth
nest generate controller auth
```

¿Por qué 3 comandos separados?
A diferencia de `users`, no queremos un CRUD completo. Solo necesitamos:
- `AuthModule`: Configuración del módulo
- `AuthService`: Lógica de autenticación
- `AuthController`: Endpoints de login/register

---

## Paso 11: Crear DTOs de Autenticación

### DTO de Login

Crea el archivo `src/auth/dto/login.dto.ts`:

```typescript
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'El email debe ser válido' })
  @IsNotEmpty({ message: 'El email es requerido' })
  email: string;

  @IsString({ message: 'La contraseña debe ser un string' })
  @IsNotEmpty({ message: 'La contraseña es requerida' })
  password: string;
}
```

### DTO de Registro

Crea el archivo `src/auth/dto/register.dto.ts`:

```typescript
import { CreateUserDto } from '../../users/dto/create-user.dto';

// Reutilizamos el CreateUserDto para el registro
export class RegisterDto extends CreateUserDto {}
```

¿Por qué reutilizar?
El registro requiere los mismos campos que crear un usuario, así que extendemos el DTO existente. Esto sigue el principio DRY (Don't Repeat Yourself).

---

## Paso 12: Implementar el Auth Service

### Teoría: Autenticación vs Autorización

Antes de implementar, es importante entender dos conceptos clave:

**Autenticación (Authentication):**
- **¿Quién eres?** - Verifica la identidad del usuario
- Proceso: Login con email/password
- Resultado: Token JWT que identifica al usuario

**Autorización (Authorization):**
- **¿Qué puedes hacer?** - Verifica los permisos del usuario
- Proceso: Verificar roles, permisos, ownership
- Resultado: Permitir o denegar acceso a recursos

**Flujo completo de Auth:**
```
1. Usuario envía credenciales → Autenticación
2. Sistema verifica credenciales → Validación
3. Si es válido, genera token → Generación JWT
4. Usuario usa token en requests → Identificación
5. Sistema verifica permisos → Autorización
6. Permite/Deniega acceso → Respuesta
```

**Responsabilidades del AuthService:**
- Registrar nuevos usuarios
- Validar credenciales en el login
- Generar tokens JWT
- Validar tokens existentes

Abre `src/auth/auth.service.ts`:

```typescript
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  /**
   * Constructor con inyección de dependencias
   * NestJS automáticamente inyecta las instancias necesarias
   * 
   * @param usersService - Servicio para gestionar usuarios
   * @param jwtService - Servicio para generar y validar tokens JWT
   */
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  /**
   * Registra un nuevo usuario en el sistema
   * @param registerDto - Datos del usuario a registrar
   * @returns Objeto con el usuario creado y su token JWT
   */
  async register(registerDto: RegisterDto) {
    // 1. Crear el usuario (el hash de la contraseña se hace en UsersService)
    const user = await this.usersService.create(registerDto);

    // 2. Generar el token JWT
    // El payload contiene información NO sensible que queremos en el token
    // 'sub' (subject) es el estándar JWT para el ID del usuario
    const payload = { sub: user.id, email: user.email };
    
    // signAsync() firma el payload con la clave secreta y genera el token
    const access_token = await this.jwtService.signAsync(payload);

    // 3. Retornar el usuario sin la contraseña y el token
    // Usamos destructuring para separar password del resto
    const { password, ...userWithoutPassword } = user;
    return {
      user: userWithoutPassword,
      access_token,
    };
  }

  /**
   * Autentica un usuario existente
   * @param loginDto - Credenciales del usuario (email y password)
   * @returns Objeto con el usuario y su token JWT
   * @throws UnauthorizedException si las credenciales son inválidas
   */
  async login(loginDto: LoginDto) {
    // 1. Buscar el usuario por email
    // findByEmail retorna el usuario CON la contraseña (necesaria para validar)
    const user = await this.usersService.findByEmail(loginDto.email);
    
    // 2. Verificar que el usuario existe
    // Importante: NO revelamos si el email existe o no por seguridad
    // Siempre usamos el mismo mensaje genérico
    if (!user) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    // 3. Verificar la contraseña usando bcrypt
    // compare() compara la contraseña en texto plano con el hash
    // Retorna true si coinciden, false si no
    const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);
    
    if (!isPasswordValid) {
      // Mismo mensaje que arriba - no revelamos qué está mal
      throw new UnauthorizedException('Credenciales inválidas');
    }

    // 4. Generar el token JWT
    // Mismo proceso que en register()
    const payload = { sub: user.id, email: user.email };
    const access_token = await this.jwtService.signAsync(payload);

    // 5. Retornar el usuario sin la contraseña y el token
    const { password, ...userWithoutPassword } = user;
    return {
      user: userWithoutPassword,
      access_token,
    };
  }

  /**
   * Valida que un usuario existe (usado por JwtStrategy)
   * @param userId - ID del usuario a validar
   * @returns Usuario encontrado o lanza excepción
   */
  async validateUser(userId: number) {
    return this.usersService.findOne(userId);
  }
}
```

Conceptos clave:

1. **Inyección de dependencias:**
   ```typescript
   constructor(
     private usersService: UsersService,
     private jwtService: JwtService,
   ) {}
   ```
   NestJS automáticamente inyecta estas dependencias.

2. **Generación de JWT:**
   ```typescript
   const payload = { sub: user.id, email: user.email };
   const access_token = await this.jwtService.signAsync(payload);
   ```
   - `sub` (subject) es el estándar JWT para el ID del usuario
   - El payload NO debe contener información sensible

3. **Verificación de contraseña:**
   ```typescript
   const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);
   ```
   - Compara la contraseña en texto plano con el hash
   - Nunca comparamos hashes directamente

4. **Seguridad:**
   - Nunca revelamos si el email existe o la contraseña es incorrecta
   - Siempre usamos el mismo mensaje: "Credenciales inválidas"

---

## Paso 13: Crear la Estrategia JWT

La estrategia JWT es el corazón de la autenticación. Define CÓMO validar los tokens.

### Teoría: Passport Strategies

**¿Qué es Passport.js?**
- Middleware de autenticación para Node.js
- Soporta más de 500 estrategias (JWT, OAuth, Local, etc.)
- Modular y fácil de integrar con NestJS

**¿Qué es una Strategy?**
Una estrategia define el **método de autenticación**:
- **Local Strategy**: Usuario/contraseña tradicional
- **JWT Strategy**: Tokens JWT
- **OAuth Strategy**: Login con Google, Facebook, etc.

**Flujo de JWT Strategy:**
```
1. Request llega con header: Authorization: Bearer <token>
2. ExtractJwt extrae el token del header
3. passport-jwt verifica la firma del token
4. Si la firma es válida, decodifica el payload
5. Llama al método validate() con el payload
6. validate() puede hacer validaciones adicionales
7. Lo que retorna validate() se añade a request.user
8. El request continúa al controller
```

**Componentes clave:**
- **PassportStrategy**: Clase base que extiende la estrategia de Passport
- **ExtractJwt**: Utilidad para extraer el token de diferentes lugares
- **validate()**: Método que se ejecuta después de verificar el token

Crea la carpeta y archivo `src/auth/strategies/jwt.strategy.ts`:

```typescript
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from '../auth.service';

/**
 * JwtStrategy - Define cómo validar tokens JWT
 * Extiende PassportStrategy con la estrategia de passport-jwt
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  /**
   * Constructor que configura la estrategia JWT
   * @param authService - Servicio para validar usuarios
   */
  constructor(private authService: AuthService) {
    // super() llama al constructor de la clase padre (Strategy)
    // Aquí configuramos CÓMO extraer y verificar el token
    super({
      // jwtFromRequest: Define de dónde extraer el token
      // fromAuthHeaderAsBearerToken() busca: "Authorization: Bearer <token>"
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      
      // ignoreExpiration: Si es false, rechaza tokens expirados
      // Si es true, acepta tokens expirados (NO recomendado)
      ignoreExpiration: false,
      
      // secretOrKey: Clave secreta para verificar la firma del token
      // DEBE ser la misma que se usó para generar el token
      // En producción: usar process.env.JWT_SECRET
      secretOrKey: 'MI_SUPER_SECRET_KEY',
    });
  }

  /**
   * Método validate() - Se ejecuta SOLO si el token es válido
   * 
   * @param payload - Payload decodificado del token JWT
   *                  Contiene: { sub: userId, email: userEmail, iat, exp }
   * @returns Objeto que se añadirá a request.user
   * @throws UnauthorizedException si el usuario no existe
   * 
   * IMPORTANTE: Este método se ejecuta DESPUÉS de que passport-jwt
   * haya verificado que:
   * 1. El token tiene una firma válida
   * 2. El token no ha expirado
   * 3. El token tiene el formato correcto
   */
  async validate(payload: any) {
    // payload.sub contiene el ID del usuario (establecido en AuthService)
    // Validamos que el usuario aún existe en la base de datos
    // Esto es importante por si el usuario fue eliminado después de generar el token
    const user = await this.authService.validateUser(payload.sub);
    
    if (!user) {
      // Si el usuario no existe, rechazamos el request
      throw new UnauthorizedException();
    }

    // Lo que retornemos aquí se añade automáticamente a request.user
    // Podemos acceder a esto en los controllers con @GetUser() o @Req()
    // Retornamos solo lo necesario (no toda la info del usuario)
    return { 
      userId: payload.sub,    // ID del usuario
      email: payload.email    // Email del usuario
    };
  }
}
```

### Explicación profunda del flujo:

**1. Extracción del token:**
```typescript
jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
```
- Busca el header `Authorization`
- Espera el formato: `Bearer eyJhbGc...`
- Extrae solo el token (sin "Bearer ")

**Otras opciones de extracción:**
```typescript
// Desde query parameter: ?token=xxx
ExtractJwt.fromUrlQueryParameter('token')

// Desde cookie
ExtractJwt.fromExtractors([(req) => req.cookies?.jwt])

// Desde body
ExtractJwt.fromBodyField('token')
```

**2. Verificación de la firma:**
```typescript
secretOrKey: 'MI_SUPER_SECRET_KEY'
```
- Usa la misma clave que generó el token
- Verifica que el token no fue alterado
- Si la firma no coincide → rechaza automáticamente

**3. Validación del payload:**
```typescript
async validate(payload: any)
```
- Solo se ejecuta si el token es válido
- Aquí puedes agregar lógica adicional
- Ejemplo: verificar que el usuario no está bloqueado

**4. Población de request.user:**
```typescript
return { userId: payload.sub, email: payload.email };
```
- Este objeto se añade a `request.user`
- Accesible en controllers y guards
- Mantén solo datos necesarios (no sensibles)

¿Cómo funciona?

1. **Configuración en el constructor:**
   - `jwtFromRequest`: Extrae el token del header `Authorization: Bearer <token>`
   - `ignoreExpiration: false`: Rechaza tokens expirados
   - `secretOrKey`: Clave secreta para verificar el token (debe ser la misma que al generar)

2. **Método validate():**
   - Se ejecuta SOLO si el token es válido y no ha expirado
   - Recibe el payload decodificado del token
   - Puede hacer validaciones adicionales (ej: verificar que el usuario existe)
   - Lo que retorna se añade a `request.user`

Flujo completo:
```
Request → Guard → Strategy → validate() → request.user → Controller
```

---

## Paso 14: Configurar el Auth Module

Ahora debemos configurar el módulo para usar JWT y Passport.

Abre `src/auth/auth.module.ts`:

```typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({
      secret: 'MI_SUPER_SECRET_KEY', // En producción, usar variable de entorno
      signOptions: { expiresIn: '24h' }, // El token expira en 24 horas
    }),
  ],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
```

Explicación de imports:

1. **UsersModule:**
   - Necesitamos acceso a `UsersService`
   - Por eso lo exportamos en el paso 9

2. **PassportModule:**
   - Provee la infraestructura de Passport.js

3. **JwtModule.register():**
   - `secret`: Clave para firmar y verificar tokens (DEBE ser la misma en Strategy)
   - `signOptions.expiresIn`: Tiempo de vida del token
   - Opciones: `'1h'`, `'7d'`, `'30m'`, etc.

IMPORTANTE en Producción:
```typescript
// Usar variables de entorno
secret: process.env.JWT_SECRET,
```

---

# FASE 4: GUARDS Y DECORADORES

## Paso 15: Crear el JWT Auth Guard

Los Guards controlan el acceso a las rutas. Vamos a crear uno personalizado.

### Teoría: Guards en NestJS

**¿Qué es un Guard?**
Un Guard es una clase que implementa la interfaz `CanActivate`. Su responsabilidad es determinar si una petición debe ser manejada por el route handler o no.

**Características de los Guards:**
- Se ejecutan **después** de los middlewares
- Se ejecutan **antes** de los interceptors y pipes
- Tienen acceso al `ExecutionContext`
- Retornan `boolean` o `Promise<boolean>`
- Si retornan `false` → Bloquean la petición (403 Forbidden)
- Si retornan `true` → Permiten la petición

**Orden de ejecución en NestJS:**
```
Request
  ↓
Middleware (express middleware)
  ↓
Guards (CanActivate)
  ↓
Interceptors (before)
  ↓
Pipes (validación y transformación)
  ↓
Route Handler (Controller method)
  ↓
Interceptors (after)
  ↓
Exception Filters
  ↓
Response
```

**Tipos de Guards:**
1. **Authentication Guards**: Verifican identidad (¿quién eres?)
2. **Authorization Guards**: Verifican permisos (¿qué puedes hacer?)
3. **Rate Limiting Guards**: Limitan peticiones
4. **Feature Flag Guards**: Habilitan/deshabilitan funcionalidades

**ExecutionContext:**
Proporciona información sobre el contexto de ejecución actual:
```typescript
context.switchToHttp().getRequest()  // Obtiene el request HTTP
context.switchToHttp().getResponse() // Obtiene el response HTTP
context.getHandler()                  // Obtiene el método del controller
context.getClass()                    // Obtiene la clase del controller
```

**Reflector:**
Permite leer metadata añadida con decoradores:
```typescript
const isPublic = this.reflector.get('isPublic', context.getHandler());
```

Crea `src/auth/guards/jwt-auth.guard.ts`:

```typescript
import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

/**
 * JwtAuthGuard - Guard personalizado para autenticación JWT
 * 
 * Extiende AuthGuard('jwt') de @nestjs/passport que:
 * 1. Extrae el token del request
 * 2. Valida el token usando JwtStrategy
 * 3. Añade el usuario a request.user
 * 
 * Añadimos funcionalidad extra:
 * - Soporte para rutas públicas con @Public()
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  /**
   * Constructor
   * @param reflector - Servicio para leer metadata de decoradores
   */
  constructor(private reflector: Reflector) {
    // super() llama al constructor de AuthGuard
    super();
  }

  /**
   * canActivate - Determina si la petición puede continuar
   * 
   * @param context - Contexto de ejecución con info del request
   * @returns boolean | Promise<boolean> - true permite, false bloquea
   * 
   * Flujo:
   * 1. Verifica si la ruta es pública
   * 2. Si es pública → permite acceso sin token
   * 3. Si no es pública → valida JWT con super.canActivate()
   */
  canActivate(context: ExecutionContext) {
    // 1. Leer metadata de la ruta para ver si es pública
    // getAllAndOverride() busca en dos lugares:
    //   - context.getHandler() → Metadata del método (@Get, @Post, etc.)
    //   - context.getClass() → Metadata de la clase (@Controller)
    // Si encuentra en el método, tiene prioridad sobre la clase
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),  // Método del controller
      context.getClass(),    // Clase del controller
    ]);

    // 2. Si la ruta está marcada como @Public(), permitir acceso
    // No se requiere token JWT
    if (isPublic) {
      return true;
    }

    // 3. Si NO es pública, ejecutar la validación JWT normal
    // super.canActivate() hace:
    //   - Extrae el token del header Authorization
    //   - Verifica la firma del token
    //   - Llama a JwtStrategy.validate()
    //   - Añade el resultado a request.user
    // Retorna true si todo es válido, lanza excepción si no
    return super.canActivate(context);
  }
}
```

### Explicación detallada del Guard:

**1. Extensión de AuthGuard:**
```typescript
extends AuthGuard('jwt')
```
- `AuthGuard` es una clase de `@nestjs/passport`
- El parámetro `'jwt'` debe coincidir con el nombre de la estrategia
- Hereda toda la lógica de validación JWT

**2. Reflector.getAllAndOverride():**
```typescript
this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
  context.getHandler(),
  context.getClass(),
])
```
- Busca metadata en múltiples lugares
- Prioriza el método sobre la clase
- Permite decoradores a nivel de clase o método

**Ejemplo de prioridad:**
```typescript
@Controller('users')
@Public()  // Metadata de clase
export class UsersController {
  @Get()
  @Public()  // Metadata de método (tiene prioridad)
  findAll() {}
}
```

**3. Lógica condicional:**
```typescript
if (isPublic) return true;
return super.canActivate(context);
```
- **Rutas públicas**: Bypass completo de autenticación
- **Rutas protegidas**: Validación JWT completa

**4. ¿Qué hace super.canActivate()?**
Internamente ejecuta:
```
1. Extrae token → ExtractJwt.fromAuthHeaderAsBearerToken()
2. Verifica firma → jwt.verify(token, secret)
3. Valida payload → JwtStrategy.validate(payload)
4. Añade a request → request.user = resultado de validate()
5. Retorna true si todo OK, lanza excepción si falla
```

Qué hace este Guard:

1. **Extiende `AuthGuard('jwt')`:**
   - Hereda la funcionalidad de validación JWT de Passport
   - El string `'jwt'` debe coincidir con el nombre de la estrategia

2. **Usa Reflector:**
   - Lee metadata de las rutas
   - Busca si la ruta tiene el decorador `@Public()`

3. **Lógica:**
   - Si la ruta es pública → permite acceso
   - Si no es pública → valida el JWT

Flujo de ejecución:
```
Request
  ↓
JwtAuthGuard.canActivate()
  ↓
¿Es pública? → Sí → Permite acceso
  ↓ No
Valida JWT → JwtStrategy.validate()
  ↓
Permite/Rechaza acceso
```

---

## Paso 16: Crear el Decorador @Public()

Este decorador marca rutas como públicas (sin autenticación requerida).

Crea `src/auth/decorators/public.decorator.ts`:

```typescript
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Decorador para marcar rutas como públicas (sin autenticación)
 * Uso: @Public() encima del método del controlador
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

¿Cómo funciona?

1. **SetMetadata:**
   - Añade metadata a la ruta
   - Key: `'isPublic'`
   - Value: `true`

2. **Uso:**
   ```typescript
   @Public()
   @Post('login')
   async login() { ... }
   ```

3. **El Guard lee esta metadata:**
   ```typescript
   const isPublic = this.reflector.getAllAndOverride(IS_PUBLIC_KEY, [...]);
   ```

---

## Paso 17: Crear el Decorador @GetUser()

Este decorador extrae el usuario del request en rutas protegidas.

Crea `src/auth/decorators/get-user.decorator.ts`:

```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Decorador para extraer el usuario del request
 * Uso: @GetUser() user: any
 * El usuario está disponible porque JwtStrategy lo añade a request.user
 */
export const GetUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);
```

¿Cómo funciona?

1. **createParamDecorator:**
   - Crea un decorador de parámetro personalizado
   - Similar a `@Body()`, `@Param()`, etc.

2. **Extrae del request:**
   ```typescript
   const request = ctx.switchToHttp().getRequest();
   return request.user;
   ```
   - `request.user` fue añadido por `JwtStrategy.validate()`

3. **Uso en controladores:**
   ```typescript
   @Get('profile')
   getProfile(@GetUser() user: any) {
     return user; // { userId: 1, email: 'test@test.com' }
   }
   ```

Ventajas:
- Código más limpio y expresivo
- Reutilizable en cualquier controlador
- Type-safe (puedes tipar el usuario)

---

## Paso 18: Implementar el Auth Controller

Ahora vamos a crear los endpoints de autenticación.

Abre `src/auth/auth.controller.ts`:

```typescript
import { Controller, Post, Body, Get, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { Public } from './decorators/public.decorator';
import { GetUser } from './decorators/get-user.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Ruta pública para registrar un nuevo usuario
   * POST /auth/register
   */
  @Public()
  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  /**
   * Ruta pública para hacer login
   * POST /auth/login
   */
  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  /**
   * Ruta protegida para obtener el perfil del usuario autenticado
   * GET /auth/profile
   * Requiere token JWT en el header: Authorization: Bearer <token>
   */
  @Get('profile')
  getProfile(@GetUser() user: any) {
    return {
      message: 'Perfil del usuario autenticado',
      user,
    };
  }
}
```

Detalles importantes:

1. **@Public() en register y login:**
   - Estas rutas NO requieren autenticación
   - Cualquiera puede registrarse o hacer login

2. **@HttpCode(HttpStatus.OK) en login:**
   - Por defecto, POST retorna 201 (Created)
   - Login debe retornar 200 (OK)

3. **@GetUser() en profile:**
   - Extrae el usuario del request
   - Solo funciona en rutas protegidas (después de pasar el Guard)

4. **Sin @Public() en profile:**
   - Esta ruta requiere autenticación
   - El Guard validará el JWT

---

## Paso 19: Aplicar el Guard Globalmente

Para proteger TODAS las rutas por defecto, aplicamos el Guard globalmente.

Abre `src/app.module.ts`:

```typescript
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';

@Module({
  imports: [UsersModule, AuthModule],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard, // Aplicar JwtAuthGuard globalmente a todas las rutas
    },
  ],
})
export class AppModule {}
```

Qué significa "globalmente":

- TODAS las rutas requieren autenticación por defecto
- Para hacer una ruta pública, usamos `@Public()`
- Es más seguro: "deny by default, allow explicitly"

Alternativa (NO recomendada):
```typescript
// Aplicar guard ruta por ruta
@UseGuards(JwtAuthGuard)
@Get('protected')
protectedRoute() { ... }
```

Problema: Es fácil olvidar proteger una ruta sensible.

---

## Paso 20: Marcar la Ruta Raíz como Pública

La ruta raíz (`/`) debe ser pública para health checks.

Abre `src/app.controller.ts`:

```typescript
import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { Public } from './auth/decorators/public.decorator';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  /**
   * Ruta pública de health check
   * GET /
   */
  @Public()
  @Get()
  getHello(): string {
    return this.appService.getHello();
  }
}
```

---

## Paso 21: Configurar Validación Global

Para que los DTOs se validen automáticamente, configuramos ValidationPipe.

Abre `src/main.ts`:

```typescript
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Habilitar validación global con class-validator
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Elimina propiedades no definidas en el DTO
      forbidNonWhitelisted: true, // Lanza error si hay propiedades extras
      transform: true, // Transforma los payloads a instancias de DTO
    }),
  );

  await app.listen(process.env.PORT ?? 3000);
  console.log('Aplicación corriendo en http://localhost:3000');
}
bootstrap();
```

Opciones del ValidationPipe:

| Opción | Efecto |
|--------|--------|
| `whitelist: true` | Elimina propiedades no definidas en el DTO |
| `forbidNonWhitelisted: true` | Rechaza requests con propiedades extras |
| `transform: true` | Convierte tipos automáticamente (string → number) |

Ejemplo:
```typescript
// DTO espera: { email, password, name }
// Request envía: { email, password, name, hacker: true }

// Con whitelist: true → elimina 'hacker'
// Con forbidNonWhitelisted: true → rechaza el request
```

---

# FASE 5: PROBAR LA APLICACIÓN

## Paso 22: Compilar y Ejecutar

Vamos a verificar que todo compile correctamente.

```bash
# Compilar
npm run build

# Si no hay errores, ejecutar en modo desarrollo
npm run start:dev
```

Deberías ver:
```
Aplicación corriendo en http://localhost:3000
```

---

## Paso 23: Probar el Registro

Vamos a registrar un nuevo usuario.

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "juan@example.com",
    "password": "password123",
    "name": "Juan Pérez"
  }'
```

Respuesta esperada:
```json
{
  "user": {
    "id": 1,
    "email": "juan@example.com",
    "name": "Juan Pérez",
    "createdAt": "2024-01-01T00:00:00.000Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Verificaciones:
- El usuario se creó correctamente
- La contraseña está hasheada (no es el texto plano)
- El ID se auto-incrementa
- El token JWT se generó correctamente

---

## Paso 24: Probar el Login

Ahora vamos a hacer login con el usuario creado.

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "juan@example.com",
    "password": "password123"
  }'
```

**Respuesta esperada:**
```json
{
  "user": {
    "id": 1,
    "email": "juan@example.com",
    "name": "Juan Pérez",
    "createdAt": "2024-01-01T00:00:00.000Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Probar con contraseña incorrecta:**
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "juan@example.com",
    "password": "incorrecta"
  }'
```

**Respuesta esperada:**
```json
{
  "statusCode": 401,
  "message": "Credenciales inválidas"
}
```

---

## Paso 25: Probar Ruta Protegida SIN Token

Intentemos acceder a una ruta protegida sin autenticación.

```bash
curl -X GET http://localhost:3000/auth/profile
```

**Respuesta esperada:**
```json
{
  "statusCode": 401,
  "message": "Unauthorized"
}
```

Perfecto! El Guard está funcionando y rechaza acceso sin token.

---

## Paso 26: Probar Ruta Protegida CON Token

Ahora vamos a acceder con un token válido.

**Primero, copia el token del login anterior, luego:**

```bash
curl -X GET http://localhost:3000/auth/profile \
  -H "Authorization: Bearer TU_TOKEN_AQUI"
```

**Reemplaza `TU_TOKEN_AQUI` con el token real.**

**Respuesta esperada:**
```json
{
  "message": "Perfil del usuario autenticado",
  "user": {
    "userId": 1,
    "email": "juan@example.com"
  }
}
```

Excelente! El Guard validó el token y permitió el acceso.

---

## Paso 27: Probar Validación de DTOs

Vamos a enviar datos inválidos para ver la validación en acción.

**Email inválido:**
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "no-es-un-email",
    "password": "123456",
    "name": "Test"
  }'
```

**Respuesta esperada:**
```json
{
  "statusCode": 400,
  "message": ["El email debe ser válido"],
  "error": "Bad Request"
}
```

**Contraseña muy corta:**
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@test.com",
    "password": "123",
    "name": "Test"
  }'
```

**Respuesta esperada:**
```json
{
  "statusCode": 400,
  "message": ["La contraseña debe tener al menos 6 caracteres"],
  "error": "Bad Request"
}
```

La validación funciona correctamente!

---

# FELICIDADES!

Has creado una aplicación NestJS completa con:

- Autenticación con JWT  
- Guards personalizados  
- Decoradores personalizados  
- Validación de datos  
- Hash de contraseñas  
- Rutas públicas y protegidas  

---

# CONCEPTOS APRENDIDOS

## 1. JWT (JSON Web Token)

Qué es:
Un token codificado que contiene información del usuario.

Estructura:
```
eyJhbGc... (Header) . eyJzdWI... (Payload) . SflKxwR... (Signature)
```

**Ventajas:**
- Stateless (no requiere sesiones en servidor)
- Puede contener información del usuario
- Verificable criptográficamente

Desventajas:
- No se puede invalidar antes de expirar
- Si se roba, es válido hasta que expire

---

## 2. Guards

Qué son:
Clases que determinan si una petición puede proceder.

Implementan:
```typescript
interface CanActivate {
  canActivate(context: ExecutionContext): boolean | Promise<boolean>;
}
```

Orden de ejecución:
```
Middleware → Guards → Interceptors → Pipes → Controller → Service
```

Tipos:
- **AuthGuard**: Verifica autenticación
- **RolesGuard**: Verifica permisos
- **ThrottlerGuard**: Rate limiting

---

## 3. Decoradores

Qué son:
Funciones que añaden metadata o modifican comportamiento.

Tipos en NestJS:

1. **Decoradores de clase:**
   ```typescript
   @Controller('users')
   @Injectable()
   ```

2. **Decoradores de método:**
   ```typescript
   @Get()
   @Post()
   @Public()
   ```

3. **Decoradores de parámetro:**
   ```typescript
   @Body()
   @Param()
   @GetUser()
   ```

Crear decorador personalizado:
```typescript
export const MyDecorator = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    // lógica
  },
);
```

---

## 4. Passport Strategies

Qué son:
Definen CÓMO autenticar (JWT, OAuth, Local, etc.)

Flujo:
```
Request → Guard → Strategy.validate() → request.user → Controller
```

Estrategias comunes:
- `passport-jwt`: Autenticación con JWT
- `passport-local`: Usuario/contraseña
- `passport-google-oauth20`: Login con Google
- `passport-facebook`: Login con Facebook

---

## 5. DTOs y Validación

Qué son los DTOs:
Data Transfer Objects - Definen la estructura de datos.

**Ventajas:**
- Validación automática
- Documentación del API
- Type safety
- Transformación de datos

Decoradores de validación:
```typescript
@IsString()
@IsEmail()
@IsNotEmpty()
@MinLength(6)
@MaxLength(100)
@IsOptional()
```

---

# PRÓXIMOS PASOS

## Mejoras que puedes implementar:

### 1. Base de Datos Real
```bash
npm install @nestjs/typeorm typeorm pg
```

### 2. Refresh Tokens
Implementar tokens de refresco para renovar el access token.

### 3. Roles y Permisos
```typescript
@Roles('admin')
@Get('admin-only')
```

### 4. Variables de Entorno
```bash
npm install @nestjs/config
```

```typescript
// .env
JWT_SECRET=mi_secreto_super_seguro
JWT_EXPIRATION=24h
```

### 5. Swagger Documentation
```bash
npm install @nestjs/swagger
```

### 6. Rate Limiting
```bash
npm install @nestjs/throttler
```

### 7. Email Verification
Enviar email de confirmación al registrarse.

### 8. Password Reset
Implementar "olvidé mi contraseña".

### 9. Two-Factor Authentication (2FA)
Autenticación de dos factores.

### 10. OAuth (Google, Facebook, GitHub)
Login con redes sociales.

---

# RECURSOS ADICIONALES

## Documentación Oficial
- [NestJS Docs](https://docs.nestjs.com)
- [Passport.js](http://www.passportjs.org/)
- [JWT.io](https://jwt.io/)

## Tutoriales
- [NestJS Authentication](https://docs.nestjs.com/security/authentication)
- [NestJS Guards](https://docs.nestjs.com/guards)
- [NestJS Custom Decorators](https://docs.nestjs.com/custom-decorators)

## Herramientas
- [Postman](https://www.postman.com/) - Testing de APIs
- [Thunder Client](https://www.thunderclient.com/) - Extension de VS Code
- [JWT Debugger](https://jwt.io/#debugger) - Decodificar tokens

---

# PREGUNTAS FRECUENTES

## ¿Por qué usar JWT en lugar de sesiones?

**JWT (Stateless):**
- Escalable (no requiere almacenamiento en servidor)
- Funciona bien con microservicios
- Mobile-friendly
- No se puede invalidar fácilmente
- Tamaño mayor que session ID

**Sesiones (Stateful):**
- Se pueden invalidar inmediatamente
- Menor tamaño
- Requiere almacenamiento (Redis, DB)
- Difícil de escalar

## ¿Es seguro almacenar el JWT en localStorage?

NO es la opción más segura debido a XSS (Cross-Site Scripting).

Opciones:
1. **httpOnly Cookie** (más seguro)
2. **localStorage** (vulnerable a XSS)
3. **sessionStorage** (se pierde al cerrar tab)

Recomendación: httpOnly Cookie + CSRF protection

## ¿Qué poner en el payload del JWT?

**SÍ incluir:**
- User ID
- Email
- Roles
- Información pública

**NO incluir:**
- Contraseñas
- Información sensible
- Datos personales (SSN, tarjetas, etc.)

Recuerda: El payload es decodificable (Base64), no encriptado.

## ¿Cómo manejar tokens expirados?

**Opciones:**

1. **Refresh Token:**
   ```
   Access Token (15min) + Refresh Token (7 días)
   ```

2. **Re-login:**
   Pedir al usuario que vuelva a hacer login.

3. **Silent Refresh:**
   Renovar automáticamente antes de expirar.

---

# RESUMEN FINAL

## Comandos usados:

```bash
# Setup
npm install -g @nestjs/cli
nest new nestjs-auth
npm install @nestjs/jwt @nestjs/passport passport passport-jwt bcrypt class-validator class-transformer
npm install -D @types/passport-jwt @types/bcrypt

# Generar recursos
nest generate resource users
nest generate module auth
nest generate service auth
nest generate controller auth

# Ejecutar
npm run start:dev
npm run build
npm run start:prod
```

## Archivos creados:

```
src/
├── auth/
│   ├── decorators/
│   │   ├── public.decorator.ts
│   │   └── get-user.decorator.ts
│   ├── guards/
│   │   └── jwt-auth.guard.ts
│   ├── strategies/
│   │   └── jwt.strategy.ts
│   ├── dto/
│   │   ├── login.dto.ts
│   │   └── register.dto.ts
│   ├── auth.controller.ts
│   ├── auth.service.ts
│   └── auth.module.ts
├── users/
│   ├── entities/user.entity.ts
│   ├── dto/create-user.dto.ts
│   ├── users.service.ts
│   └── users.module.ts
├── app.module.ts
└── main.ts
```

## Flujo completo:

```
1. Usuario se registra → POST /auth/register
2. Se hashea la contraseña con bcrypt
3. Se crea el usuario en memoria
4. Se genera un JWT
5. Se retorna usuario + token

6. Usuario hace login → POST /auth/login
7. Se busca el usuario por email
8. Se verifica la contraseña con bcrypt
9. Se genera un JWT
10. Se retorna usuario + token

11. Usuario accede a ruta protegida → GET /auth/profile
12. JwtAuthGuard intercepta el request
13. Verifica si la ruta es @Public() → No
14. Extrae el token del header Authorization
15. JwtStrategy valida el token
16. Si es válido, añade user a request
17. Controller recibe el user con @GetUser()
18. Retorna la información del perfil
```

---

Felicidades por completar esta guía!

Ahora tienes una base sólida para construir aplicaciones NestJS con autenticación profesional.

Siguiente paso: Implementa una de las mejoras sugeridas y sigue aprendiendo.

Happy coding!

