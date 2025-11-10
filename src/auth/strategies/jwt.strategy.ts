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
