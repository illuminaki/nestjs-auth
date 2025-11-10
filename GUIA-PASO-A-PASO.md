# 📖 GUÍA PASO A PASO - NestJS Auth con JWT

Esta guía te llevará paso a paso para crear una aplicación NestJS completa con autenticación JWT, guards y decoradores personalizados.

## 📋 Requisitos Previos

Antes de comenzar, asegúrate de tener instalado:
- Node.js (v18 o superior)
- npm o yarn
- Un editor de código (VS Code recomendado)
- Conocimientos básicos de TypeScript y Node.js

---

## 🎯 ¿Qué vamos a construir?

Una API REST con:
- ✅ Sistema de registro y login
- ✅ Autenticación con JWT
- ✅ Rutas públicas y protegidas
- ✅ Guards personalizados
- ✅ Decoradores personalizados
- ✅ Validación de datos
- ✅ Hash de contraseñas

---

# FASE 1: SETUP INICIAL

## Paso 1: Instalar el CLI de NestJS

El CLI de NestJS nos ayudará a generar código y estructurar el proyecto correctamente.

```bash
npm install -g @nestjs/cli
```

**¿Por qué?** El CLI de NestJS automatiza la creación de módulos, controladores, servicios y más, siguiendo las mejores prácticas.

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

**¿Qué hace este comando?**
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

**¿Qué hace cada paquete?**

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

**¿Qué hace este comando?**
- Compila el código TypeScript
- Inicia el servidor en modo desarrollo
- Habilita hot-reload (recarga automática al hacer cambios)

**Deberías ver:**
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

✅ **¡Perfecto!** El proyecto base está funcionando.

---

# FASE 2: MÓDULO USERS

## Paso 5: Generar el Módulo Users

Vamos a usar el CLI de NestJS para generar un módulo completo de usuarios con CRUD.

```bash
nest generate resource users
```

**El CLI te preguntará:**

1. **¿Qué capa de transporte usas?** → Selecciona `REST API`
2. **¿Generar puntos de entrada CRUD?** → Selecciona `Yes`

**¿Qué genera este comando?**
```
CREATE src/users/users.controller.ts
CREATE src/users/users.module.ts
CREATE src/users/users.service.ts
CREATE src/users/dto/create-user.dto.ts
CREATE src/users/dto/update-user.dto.ts
CREATE src/users/entities/user.entity.ts
UPDATE src/app.module.ts
```

**¿Por qué usar el CLI?**
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

**¿Qué es una Entity?**
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

**¿Qué hacen estos decoradores?**

| Decorador | Función |
|-----------|---------|
| `@IsEmail()` | Valida que sea un email válido |
| `@IsString()` | Valida que sea un string |
| `@IsNotEmpty()` | Valida que no esté vacío |
| `@MinLength(6)` | Valida longitud mínima |

**Beneficio:** Si alguien envía datos inválidos, NestJS automáticamente rechazará la petición con un mensaje de error claro.

---

## Paso 8: Implementar el Users Service

El Service contiene la lógica de negocio. Aquí manejaremos usuarios en memoria.

Abre `src/users/users.service.ts` y reemplaza todo el contenido:

```typescript
import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  // Simulamos una base de datos en memoria
  private users: User[] = [];
  private currentId = 1;

  async create(createUserDto: CreateUserDto): Promise<User> {
    // Verificar si el email ya existe
    const existingUser = this.users.find(u => u.email === createUserDto.email);
    if (existingUser) {
      throw new ConflictException('El email ya está registrado');
    }

    // Hashear la contraseña
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    // Crear el nuevo usuario
    const newUser: User = {
      id: this.currentId++,
      email: createUserDto.email,
      password: hashedPassword,
      name: createUserDto.name,
      createdAt: new Date(),
    };

    this.users.push(newUser);
    return newUser;
  }

  findAll(): User[] {
    // Retornar usuarios sin la contraseña
    return this.users.map(({ password, ...user }) => user as User);
  }

  findOne(id: number): User {
    const user = this.users.find(u => u.id === id);
    if (!user) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }
    
    // Retornar sin la contraseña
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword as User;
  }

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

**¿Por qué exportar?**
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

**¿Por qué 3 comandos separados?**
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

**¿Por qué reutilizar?**
El registro requiere los mismos campos que crear un usuario, así que extendemos el DTO existente. Esto sigue el principio DRY (Don't Repeat Yourself).

---

## Paso 12: Implementar el Auth Service

Abre `src/auth/auth.service.ts`:

```typescript
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto) {
    // Crear el usuario (el hash de la contraseña se hace en UsersService)
    const user = await this.usersService.create(registerDto);

    // Generar el token JWT
    const payload = { sub: user.id, email: user.email };
    const access_token = await this.jwtService.signAsync(payload);

    // Retornar el usuario sin la contraseña y el token
    const { password, ...userWithoutPassword } = user;
    return {
      user: userWithoutPassword,
      access_token,
    };
  }

  async login(loginDto: LoginDto) {
    // Buscar el usuario por email
    const user = await this.usersService.findByEmail(loginDto.email);
    
    if (!user) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    // Verificar la contraseña
    const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);
    
    if (!isPasswordValid) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    // Generar el token JWT
    const payload = { sub: user.id, email: user.email };
    const access_token = await this.jwtService.signAsync(payload);

    // Retornar el usuario sin la contraseña y el token
    const { password, ...userWithoutPassword } = user;
    return {
      user: userWithoutPassword,
      access_token,
    };
  }

  async validateUser(userId: number) {
    return this.usersService.findOne(userId);
  }
}
```

**Conceptos clave:**

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

Crea la carpeta y archivo `src/auth/strategies/jwt.strategy.ts`:

```typescript
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: 'MI_SUPER_SECRET_KEY', // En producción, usar variable de entorno
    });
  }

  async validate(payload: any) {
    // Este método se ejecuta si el token es válido
    // payload contiene la información que pusimos en el token (sub, email)
    
    const user = await this.authService.validateUser(payload.sub);
    
    if (!user) {
      throw new UnauthorizedException();
    }

    // Lo que retornemos aquí se añade a request.user
    return { userId: payload.sub, email: payload.email };
  }
}
```

**¿Cómo funciona?**

1. **Configuración en el constructor:**
   - `jwtFromRequest`: Extrae el token del header `Authorization: Bearer <token>`
   - `ignoreExpiration: false`: Rechaza tokens expirados
   - `secretOrKey`: Clave secreta para verificar el token (debe ser la misma que al generar)

2. **Método validate():**
   - Se ejecuta SOLO si el token es válido y no ha expirado
   - Recibe el payload decodificado del token
   - Puede hacer validaciones adicionales (ej: verificar que el usuario existe)
   - Lo que retorna se añade a `request.user`

**Flujo completo:**
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

**Explicación de imports:**

1. **UsersModule:**
   - Necesitamos acceso a `UsersService`
   - Por eso lo exportamos en el paso 9

2. **PassportModule:**
   - Provee la infraestructura de Passport.js

3. **JwtModule.register():**
   - `secret`: Clave para firmar y verificar tokens (DEBE ser la misma en Strategy)
   - `signOptions.expiresIn`: Tiempo de vida del token
   - Opciones: `'1h'`, `'7d'`, `'30m'`, etc.

**⚠️ Importante en Producción:**
```typescript
// Usar variables de entorno
secret: process.env.JWT_SECRET,
```

---

# FASE 4: GUARDS Y DECORADORES

## Paso 15: Crear el JWT Auth Guard

Los Guards controlan el acceso a las rutas. Vamos a crear uno personalizado.

Crea `src/auth/guards/jwt-auth.guard.ts`:

```typescript
import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    // Verificar si la ruta está marcada como pública
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Si es pública, permitir acceso sin autenticación
    if (isPublic) {
      return true;
    }

    // Si no es pública, ejecutar la validación JWT normal
    return super.canActivate(context);
  }
}
```

**¿Qué hace este Guard?**

1. **Extiende `AuthGuard('jwt')`:**
   - Hereda la funcionalidad de validación JWT de Passport
   - El string `'jwt'` debe coincidir con el nombre de la estrategia

2. **Usa Reflector:**
   - Lee metadata de las rutas
   - Busca si la ruta tiene el decorador `@Public()`

3. **Lógica:**
   - Si la ruta es pública → permite acceso
   - Si no es pública → valida el JWT

**Flujo de ejecución:**
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

**¿Cómo funciona?**

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

**¿Cómo funciona?**

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

**Ventajas:**
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

**Detalles importantes:**

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

**¿Qué significa "globalmente"?**

- TODAS las rutas requieren autenticación por defecto
- Para hacer una ruta pública, usamos `@Public()`
- Es más seguro: "deny by default, allow explicitly"

**Alternativa (NO recomendada):**
```typescript
// Aplicar guard ruta por ruta
@UseGuards(JwtAuthGuard)
@Get('protected')
protectedRoute() { ... }
```

**Problema:** Es fácil olvidar proteger una ruta sensible.

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
  console.log('🚀 Aplicación corriendo en http://localhost:3000');
}
bootstrap();
```

**Opciones del ValidationPipe:**

| Opción | Efecto |
|--------|--------|
| `whitelist: true` | Elimina propiedades no definidas en el DTO |
| `forbidNonWhitelisted: true` | Rechaza requests con propiedades extras |
| `transform: true` | Convierte tipos automáticamente (string → number) |

**Ejemplo:**
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

**Deberías ver:**
```
🚀 Aplicación corriendo en http://localhost:3000
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

**✅ Verificaciones:**
- ✓ El usuario se creó con ID 1
- ✓ La contraseña NO aparece en la respuesta
- ✓ Se generó un token JWT
- ✓ El token es un string largo codificado en Base64

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

**✅ Perfecto!** El Guard está funcionando y rechaza acceso sin token.

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

**✅ Excelente!** El Guard validó el token y permitió el acceso.

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

**✅ La validación funciona correctamente!**

---

# 🎉 ¡FELICIDADES!

Has creado una aplicación NestJS completa con:

✅ Autenticación con JWT  
✅ Guards personalizados  
✅ Decoradores personalizados  
✅ Validación de datos  
✅ Hash de contraseñas  
✅ Rutas públicas y protegidas  

---

# 📚 CONCEPTOS APRENDIDOS

## 1. JWT (JSON Web Token)

**¿Qué es?**
Un token codificado que contiene información del usuario.

**Estructura:**
```
eyJhbGc... (Header) . eyJzdWI... (Payload) . SflKxwR... (Signature)
```

**Ventajas:**
- Stateless (no requiere sesiones en servidor)
- Puede contener información del usuario
- Verificable criptográficamente

**Desventajas:**
- No se puede invalidar antes de expirar
- Si se roba, es válido hasta que expire

---

## 2. Guards

**¿Qué son?**
Clases que determinan si una petición puede proceder.

**Implementan:**
```typescript
interface CanActivate {
  canActivate(context: ExecutionContext): boolean | Promise<boolean>;
}
```

**Orden de ejecución:**
```
Middleware → Guards → Interceptors → Pipes → Controller → Service
```

**Tipos:**
- **AuthGuard**: Verifica autenticación
- **RolesGuard**: Verifica permisos
- **ThrottlerGuard**: Rate limiting

---

## 3. Decoradores

**¿Qué son?**
Funciones que añaden metadata o modifican comportamiento.

**Tipos en NestJS:**

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

**Crear decorador personalizado:**
```typescript
export const MyDecorator = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    // lógica
  },
);
```

---

## 4. Passport Strategies

**¿Qué son?**
Definen CÓMO autenticar (JWT, OAuth, Local, etc.)

**Flujo:**
```
Request → Guard → Strategy.validate() → request.user → Controller
```

**Estrategias comunes:**
- `passport-jwt`: Autenticación con JWT
- `passport-local`: Usuario/contraseña
- `passport-google-oauth20`: Login con Google
- `passport-facebook`: Login con Facebook

---

## 5. DTOs y Validación

**¿Qué son los DTOs?**
Data Transfer Objects - Definen la estructura de datos.

**Ventajas:**
- Validación automática
- Documentación del API
- Type safety
- Transformación de datos

**Decoradores de validación:**
```typescript
@IsString()
@IsEmail()
@IsNotEmpty()
@MinLength(6)
@MaxLength(100)
@IsOptional()
```

---

# 🚀 PRÓXIMOS PASOS

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

# 📖 RECURSOS ADICIONALES

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

# ❓ PREGUNTAS FRECUENTES

## ¿Por qué usar JWT en lugar de sesiones?

**JWT (Stateless):**
- ✅ Escalable (no requiere almacenamiento en servidor)
- ✅ Funciona bien con microservicios
- ✅ Mobile-friendly
- ❌ No se puede invalidar fácilmente
- ❌ Tamaño mayor que session ID

**Sesiones (Stateful):**
- ✅ Se pueden invalidar inmediatamente
- ✅ Menor tamaño
- ❌ Requiere almacenamiento (Redis, DB)
- ❌ Difícil de escalar

## ¿Es seguro almacenar el JWT en localStorage?

**NO es la opción más segura** debido a XSS (Cross-Site Scripting).

**Opciones:**
1. **httpOnly Cookie** (más seguro)
2. **localStorage** (vulnerable a XSS)
3. **sessionStorage** (se pierde al cerrar tab)

**Recomendación:** httpOnly Cookie + CSRF protection

## ¿Qué poner en el payload del JWT?

**✅ SÍ incluir:**
- User ID
- Email
- Roles
- Información pública

**❌ NO incluir:**
- Contraseñas
- Información sensible
- Datos personales (SSN, tarjetas, etc.)

**Recuerda:** El payload es decodificable (Base64), no encriptado.

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

# 🎯 RESUMEN FINAL

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

**¡Felicidades por completar esta guía!** 🎉

Ahora tienes una base sólida para construir aplicaciones NestJS con autenticación profesional.

**¿Siguiente paso?** Implementa una de las mejoras sugeridas y sigue aprendiendo.

**Happy coding!** 💻✨

