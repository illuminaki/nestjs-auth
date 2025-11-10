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
