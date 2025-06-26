import {
  Controller,
  Post,
  Body,
  Get,
  UseGuards,
  Request,
  Put,
  Param,
  HttpException,
  HttpStatus,
  Query,
  Response,
} from '@nestjs/common';
import { Response as ExpressResponse, Request as ExpressRequest } from 'express';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RoleGuard } from './guards/role.guard';
import { Roles } from './roles.decorator';
import { UserRole } from '../enums/enums';
import {
  RegisterGestionnaireDto,
  CreateBailleurDto,
  CreateLocataireDto,
  LoginMatriculeDto,
  ChangePasswordDto,
  LoginDto
} from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // Inscription d'un gestionnaire (accessible publiquement)
  @Post('register/gestionnaire')
  async registerGestionnaire(
    @Body() registerDto: RegisterGestionnaireDto,
    @Response() res: ExpressResponse,
  ) {
    try {
      const result = await this.authService.registerGestionnaire(registerDto, res);
      return res.json({
        message: 'Gestionnaire créé avec succès',
        data: result,
      });
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur lors de la création du gestionnaire',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  // Création d'un bailleur (réservé aux gestionnaires)
  @Post('create/bailleur')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(UserRole.GESTIONNAIRE)
  async createBailleur(@Body() createBailleurDto: CreateBailleurDto) {
    try {
      const result = await this.authService.createBailleur(createBailleurDto);
      return {
        message: 'Bailleur créé avec succès',
        data: result,
      };
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur lors de la création du bailleur',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  // Création d'un locataire (réservé aux gestionnaires et bailleurs)
  @Post('create/locataire')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(UserRole.GESTIONNAIRE, UserRole.BAILLEUR)
  async createLocataire(@Body() createLocataireDto: CreateLocataireDto) {
    try {
      const result = await this.authService.createLocataire(createLocataireDto);
      return {
        message: 'Locataire créé avec succès',
        data: result,
      };
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur lors de la création du locataire',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  // Connexion par email (gestionnaires et bailleurs)
  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Response() res: ExpressResponse,
  ) {
    try {
      const result = await this.authService.login(loginDto, res);
      return res.json({
        message: 'Connexion réussie',
        data: result,
      });
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur de connexion',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }




  // Connexion par matricule (locataires)
  @Post('login/matricule')
  async loginWithMatricule(
    @Body() loginDto: LoginMatriculeDto,
    @Response() res: ExpressResponse,
  ) {
    try {
      const result = await this.authService.loginWithMatricule(loginDto, res);
      return res.json({
        message: 'Connexion réussie',
        data: result,
      });
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur de connexion',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  // Déconnexion
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(@Response() res: ExpressResponse) {
    try {
      const result = await this.authService.logout(res);
      return res.json(result);
    } catch (error) {
      throw new HttpException(
        'Erreur lors de la déconnexion',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // Rafraîchir le token
  @Post('refresh')
  async refreshToken(
    @Request() req: ExpressRequest,
    @Response() res: ExpressResponse,
  ) {
    try {
      const refreshToken = req.cookies?.refresh_token;
      
      if (!refreshToken) {
        throw new HttpException(
          'Token de rafraîchissement manquant',
          HttpStatus.UNAUTHORIZED,
        );
      }

      const result = await this.authService.refreshToken(refreshToken, res);
      return res.json({
        message: 'Token rafraîchi avec succès',
        data: result,
      });
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur lors du rafraîchissement du token',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  // Obtenir les informations de l'utilisateur connecté
  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getCurrentUser(@Request() req) {
    try {
      const user = await this.authService.getCurrentUser(req.user.id);
      return {
        message: 'Informations utilisateur récupérées',
        data: user,
      };
    } catch (error) {
      throw new HttpException(
        'Utilisateur non trouvé',
        HttpStatus.NOT_FOUND,
      );
    }
  }

  // Vérifier le statut de l'authentification
  @Get('check')
  @UseGuards(JwtAuthGuard)
  async checkAuth(@Request() req) {
    return {
      message: 'Utilisateur authentifié',
      data: {
        id: req.user.id,
        email: req.user.email,
        matricule: req.user.matricule,
        role: req.user.role,
      },
    };
  }

  // Obtenir un utilisateur par ID (gestionnaires uniquement)
  @Get('user/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(UserRole.GESTIONNAIRE)
  async getUserById(@Param('id') id: string) {
    try {
      const user = await this.authService.getUserById(id);
      return {
        message: 'Utilisateur trouvé',
        data: user,
      };
    } catch (error) {
      throw new HttpException(
        'Utilisateur non trouvé',
        HttpStatus.NOT_FOUND,
      );
    }
  }

  // Obtenir tous les utilisateurs (gestionnaires uniquement)
  @Get('users')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(UserRole.GESTIONNAIRE)
  async getAllUsers(
    @Query('role') role?: string,
    @Query('actif') actif?: string,
  ) {
    try {
      const isActif = actif !== undefined ? actif === 'true' : undefined;
      const users = await this.authService.getAllUsersWithFilters(role, isActif);
      return {
        message: 'Liste des utilisateurs récupérée',
        data: users,
        count: users.length,
      };
    } catch (error) {
      throw new HttpException(
        'Erreur lors de la récupération des utilisateurs',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // Obtenir les statistiques des utilisateurs (gestionnaires uniquement)
  @Get('stats')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(UserRole.GESTIONNAIRE)
  async getUsersStats() {
    try {
      const stats = await this.authService.getUsersStats();
      return {
        message: 'Statistiques des utilisateurs récupérées',
        data: stats,
      };
    } catch (error) {
      throw new HttpException(
        'Erreur lors de la récupération des statistiques',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // Changer le mot de passe (gestionnaires et bailleurs)
  @Put('change-password')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(UserRole.GESTIONNAIRE, UserRole.BAILLEUR)
  async changePassword(
    @Request() req,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    try {
      await this.authService.changePassword(req.user.id, changePasswordDto);
      return {
        message: 'Mot de passe modifié avec succès',
      };
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur lors de la modification du mot de passe',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  // Désactiver un compte utilisateur (gestionnaires uniquement)
  @Put('deactivate/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(UserRole.GESTIONNAIRE)
  async deactivateUser(@Param('id') id: string) {
    try {
      await this.authService.toggleUserStatus(id, false);
      return {
        message: 'Compte utilisateur désactivé avec succès',
      };
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur lors de la désactivation du compte',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  // Réactiver un compte utilisateur (gestionnaires uniquement)
  @Put('activate/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(UserRole.GESTIONNAIRE)
  async activateUser(@Param('id') id: string) {
    try {
      await this.authService.toggleUserStatus(id, true);
      return {
        message: 'Compte utilisateur réactivé avec succès',
      };
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur lors de la réactivation du compte',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  // Changer le statut d'un utilisateur (gestionnaires uniquement)
  @Put('toggle-status/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(UserRole.GESTIONNAIRE)
  async toggleUserStatus(
    @Param('id') id: string,
    @Body() body: { actif: boolean },
  ) {
    try {
      const user = await this.authService.toggleUserStatus(id, body.actif);
      return {
        message: `Compte utilisateur ${body.actif ? 'activé' : 'désactivé'} avec succès`,
        data: user,
      };
    } catch (error) {
      throw new HttpException(
        error.message || 'Erreur lors de la modification du statut',
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}