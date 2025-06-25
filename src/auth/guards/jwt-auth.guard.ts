import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private jwtService: JwtService) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest<Request>();
    
    // Extraire le token depuis les cookies
    const token = this.extractTokenFromCookie(request);
    
    if (token) {
      // Ajouter le token dans l'en-tête Authorization pour la stratégie JWT
      request.headers.authorization = `Bearer ${token}`;
    }
    
    return super.canActivate(context);
  }

  private extractTokenFromCookie(request: Request): string | null {
    // Chercher le token dans les cookies (access_token)
    if (request.cookies && request.cookies.access_token) {
      return request.cookies.access_token;
    }
    
    // Fallback: chercher dans l'en-tête Authorization
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    
    return null;
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      throw err || new UnauthorizedException('Token invalide ou expiré');
    }
    return user;
  }
}