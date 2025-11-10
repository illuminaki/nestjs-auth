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
