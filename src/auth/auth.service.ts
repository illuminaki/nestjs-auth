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
