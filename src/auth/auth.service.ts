import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';
import { Utilisateur } from '../users/entities/user.entity';
import { UserRole } from '../enums/enums';
import {
  RegisterGestionnaireDto,
  CreateBailleurDto,
  CreateLocataireDto,
  LoginMatriculeDto,
  ChangePasswordDto,
  LoginDto
} from './dto/auth.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Utilisateur)
    private readonly utilisateurRepository: Repository<Utilisateur>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  // Génération d'un matricule unique pour les locataires
  private async generateUniqueMatricule(): Promise<string> {
    let matricule: string = '';
    let exists = true;

    while (exists) {
      const year = new Date().getFullYear();
      const random = Math.floor(Math.random() * 99999).toString().padStart(5, '0');
      matricule = `LOC-${year}-${random}`;

      const existingUser = await this.utilisateurRepository.findOne({
        where: { matricule },
      });
      exists = !!existingUser;
    }

    return matricule;
  }

  // Hachage du mot de passe
  private async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }

  // Vérification du mot de passe
  private async verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  // Génération des tokens JWT
  private generateTokens(user: Utilisateur) {
    const payload = {
      sub: user.id,
      email: user.email,
      matricule: user.matricule,
      role: user.role,
    };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn: this.configService.get<string>('JWT_EXPIRES_IN') || '15m',
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || '7d',
    });

    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        nom: user.nom,
        prenom: user.prenom,
        email: user.email,
        matricule: user.matricule,
        role: user.role,
        actif: user.actif,
      },
    };
  }

  // Configuration des cookies
  private setCookies(response: Response, accessToken: string, refreshToken: string) {
    const isProduction = this.configService.get<string>('NODE_ENV') === 'production';

    // Cookie pour l'access token (15 minutes)
    response.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    // Cookie pour le refresh token (7 jours)
    response.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
    });
  }

  // Suppression des cookies
  private clearCookies(response: Response) {
    response.clearCookie('access_token');
    response.clearCookie('refresh_token');
  }

  // Inscription d'un gestionnaire
  async registerGestionnaire(registerDto: RegisterGestionnaireDto, response: Response) {
    const { email, motDePasse, nom, prenom, telephone, adresse } = registerDto;

    const existingUser = await this.utilisateurRepository.findOne({
      where: { email },
    });

    if (existingUser) {
      throw new HttpException('Cet email est déjà utilisé', HttpStatus.CONFLICT);
    }

    const telephoneExistant = await this.utilisateurRepository.findOne({
      where: { telephone },
    });
    if (telephoneExistant) {
      throw new HttpException('Ce numéro de téléphone est déjà utilisé', HttpStatus.CONFLICT);
    }

    const hashedPassword = await this.hashPassword(motDePasse);

    const gestionnaire = this.utilisateurRepository.create({
      nom,
      prenom,
      email,
      telephone,
      adresse,
      motDePasse: hashedPassword,
      role: UserRole.GESTIONNAIRE,
      actif: true,
    });

    const savedUser = await this.utilisateurRepository.save(gestionnaire);
    const tokens = this.generateTokens(savedUser);

    this.setCookies(response, tokens.accessToken, tokens.refreshToken);

    return tokens.user;
  }

  // Création d'un bailleur par un gestionnaire
  async createBailleur(createBailleurDto: CreateBailleurDto) {
    const { email, motDePasse, nom, prenom, telephone, adresse } = createBailleurDto;

    const existingUser = await this.utilisateurRepository.findOne({
      where: { email },
    });

    if (existingUser) {
      throw new HttpException('Cet email est déjà utilisé', HttpStatus.CONFLICT);
    }

    const hashedPassword = await this.hashPassword(motDePasse);

    const bailleur = this.utilisateurRepository.create({
      nom,
      prenom,
      email,
      telephone,
      adresse,
      motDePasse: hashedPassword,
      role: UserRole.BAILLEUR,
      actif: true,
    });

    const savedUser = await this.utilisateurRepository.save(bailleur);

    return {
      id: savedUser.id,
      nom: savedUser.nom,
      prenom: savedUser.prenom,
      email: savedUser.email,
      role: savedUser.role,
      actif: savedUser.actif,
    };
  }

  // Création d'un locataire
  async createLocataire(createLocataireDto: CreateLocataireDto) {
    const { nom, prenom, telephone, adresse } = createLocataireDto;

    const matricule = await this.generateUniqueMatricule();

    const locataire = this.utilisateurRepository.create({
      nom,
      prenom,
      telephone,
      adresse,
      matricule,
      role: UserRole.LOCATAIRE,
      actif: true,
    });

    const savedUser = await this.utilisateurRepository.save(locataire);

    return {
      id: savedUser.id,
      nom: savedUser.nom,
      prenom: savedUser.prenom,
      matricule: savedUser.matricule,
      role: savedUser.role,
      actif: savedUser.actif,
    };
  }

  // Connexion par email (gestionnaires et bailleurs)
 async login(loginDto: LoginDto, response: Response) {
    const { identifiant, motDePasse } = loginDto;
    
    // Détecter automatiquement si c'est un email ou un téléphone
    const isEmail = this.isEmail(identifiant);
    const isPhone = this.isPhoneNumber(identifiant);
    
    if (!isEmail && !isPhone) {
      throw new HttpException(
        'Format d\'identifiant invalide. Veuillez fournir un email ou un numéro de téléphone valide',
        HttpStatus.BAD_REQUEST
      );
    }
    
    let user;
    
    if (isEmail) {
      // Connexion par email
      user = await this.loginByEmail(identifiant, motDePasse);
    } else if (isPhone) {
      // Connexion par téléphone
      user = await this.loginByPhone(identifiant, motDePasse);
    }
    
    if (!user.actif) {
      throw new HttpException('Compte désactivé', HttpStatus.FORBIDDEN);
    }
    
    const tokens = this.generateTokens(user);
    this.setCookies(response, tokens.accessToken, tokens.refreshToken);
    return tokens.user;
  }
  
  private async loginByEmail(email: string, motDePasse: string) {
    const user = await this.utilisateurRepository.findOne({
      where: { email },
    });
    
    if (!user) {
      throw new HttpException('Identifiant ou mot de passe incorrect', HttpStatus.UNAUTHORIZED);
    }
    
    if (user.role === UserRole.LOCATAIRE) {
      throw new HttpException('Accès non autorisé pour ce type de compte', HttpStatus.FORBIDDEN);
    }
    
    const isPasswordValid = await this.verifyPassword(motDePasse, user.motDePasse);
    if (!isPasswordValid) {
      throw new HttpException('Identifiant ou mot de passe incorrect', HttpStatus.UNAUTHORIZED);
    }
    
    return user;
  }
  
  // Méthode privée pour connexion par téléphone
  private async loginByPhone(telephone: string, motDePasse: string) {
    // Normaliser le numéro de téléphone
    const normalizedPhone = this.normalizePhoneNumber(telephone);
    
    const user = await this.utilisateurRepository.findOne({
      where: { telephone: normalizedPhone },
    });
    
    if (!user) {
      throw new HttpException('Identifiant ou mot de passe incorrect', HttpStatus.UNAUTHORIZED);
    }
    
    // Vérifier que seuls les gestionnaires et bailleurs peuvent se connecter par téléphone
    if (user.role === UserRole.LOCATAIRE) {
      throw new HttpException('Connexion par téléphone non autorisée pour les locataires', HttpStatus.FORBIDDEN);
    }
    
    if (user.role !== UserRole.GESTIONNAIRE && user.role !== UserRole.BAILLEUR) {
      throw new HttpException('Accès non autorisé pour ce type de compte', HttpStatus.FORBIDDEN);
    }
    
    const isPasswordValid = await this.verifyPassword(motDePasse, user.motDePasse);
    if (!isPasswordValid) {
      throw new HttpException('Identifiant ou mot de passe incorrect', HttpStatus.UNAUTHORIZED);
    }
    
    return user;
  }
  

  // Méthode utilitaire pour normaliser les numéros de téléphone
  private normalizePhoneNumber(phone: string): string {
    // Enlever les espaces et caractères spéciaux
    let normalized = phone.replace(/[\s\-\(\)]/g, '');
    
    // Enlever le préfixe +237 ou 237 s'il existe
    if (normalized.startsWith('+237')) {
      normalized = normalized.substring(4);
    } else if (normalized.startsWith('237')) {
      normalized = normalized.substring(3);
    }
    
    return normalized;
  }
    // Méthode utilitaire pour détecter si c'est un email
  private isEmail(identifiant: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(identifiant);
  }
  
  // Méthode utilitaire pour détecter si c'est un numéro de téléphone
  private isPhoneNumber(identifiant: string): boolean {
    // Regex pour numéros camerounais : +237xxxxxxxx, 237xxxxxxxx, ou xxxxxxxx (commençant par 6 ou 7)
    const phoneRegex = /^(\+237|237)?[67][0-9]{8}$/;
    return phoneRegex.test(identifiant.replace(/[\s\-\(\)]/g, ''));
  }

  // Connexion par matricule (locataires)
  async loginWithMatricule(loginDto: LoginMatriculeDto, response: Response) {
    const { matricule } = loginDto;

    const user = await this.utilisateurRepository.findOne({
      where: { matricule },
    });

    if (!user) {
      throw new HttpException('Matricule incorrect', HttpStatus.UNAUTHORIZED);
    }

    if (user.role !== UserRole.LOCATAIRE) {
      throw new HttpException('Accès non autorisé pour ce type de compte', HttpStatus.FORBIDDEN);
    }

    if (!user.actif) {
      throw new HttpException('Compte désactivé', HttpStatus.FORBIDDEN);
    }

    const tokens = this.generateTokens(user);
    this.setCookies(response, tokens.accessToken, tokens.refreshToken);

    return tokens.user;
  }

  // Déconnexion
  async logout(response: Response) {
    this.clearCookies(response);
    return { message: 'Déconnexion réussie' };
  }

  // Rafraîchir le token
  async refreshToken(refreshToken: string, response: Response) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });

      const user = await this.utilisateurRepository.findOne({
        where: { id: payload.sub },
      });

      if (!user || !user.actif) {
        throw new HttpException('Utilisateur non trouvé ou désactivé', HttpStatus.UNAUTHORIZED);
      }

      const tokens = this.generateTokens(user);
      this.setCookies(response, tokens.accessToken, tokens.refreshToken);

      return tokens.user;
    } catch (error) {
      throw new HttpException('Token de rafraîchissement invalide', HttpStatus.UNAUTHORIZED);
    }
  }

  // Obtenir l'utilisateur connecté
  async getCurrentUser(userId: string) {
    const user = await this.utilisateurRepository.findOne({
      where: { id: userId },
      select: ['id', 'nom', 'prenom', 'email', 'telephone', 'adresse', 'matricule', 'role', 'actif', 'creeLe'],
    });

    if (!user) {
      throw new HttpException('Utilisateur non trouvé', HttpStatus.NOT_FOUND);
    }

    return user;
  }

  // Obtenir un utilisateur par ID
  async getUserById(id: string) {
    const user = await this.utilisateurRepository.findOne({
      where: { id },
      select: ['id', 'nom', 'prenom', 'email', 'telephone', 'adresse', 'matricule', 'role', 'actif', 'creeLe'],
    });

    if (!user) {
      throw new HttpException('Utilisateur non trouvé', HttpStatus.NOT_FOUND);
    }

    return user;
  }

  // Obtenir tous les utilisateurs
  async getAllUsers() {
    return this.utilisateurRepository.find({
      select: ['id', 'nom', 'prenom', 'email', 'telephone', 'matricule', 'role', 'actif', 'creeLe'],
      order: { creeLe: 'DESC' },
    });
  }

  // Changer le mot de passe
  async changePassword(userId: string, changePasswordDto: ChangePasswordDto) {
    const { ancienMotDePasse, nouveauMotDePasse } = changePasswordDto;

    const user = await this.utilisateurRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new HttpException('Utilisateur non trouvé', HttpStatus.NOT_FOUND);
    }

    const isOldPasswordValid = await this.verifyPassword(ancienMotDePasse, user.motDePasse);
    if (!isOldPasswordValid) {
      throw new HttpException('Ancien mot de passe incorrect', HttpStatus.BAD_REQUEST);
    }

    const hashedNewPassword = await this.hashPassword(nouveauMotDePasse);

    await this.utilisateurRepository.update(userId, {
      motDePasse: hashedNewPassword,
    });

    return { message: 'Mot de passe modifié avec succès' };
  }

  // Activer/Désactiver un utilisateur (gestionnaires uniquement)
  async toggleUserStatus(userId: string, actif: boolean) {
    const user = await this.utilisateurRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new HttpException('Utilisateur non trouvé', HttpStatus.NOT_FOUND);
    }

    await this.utilisateurRepository.update(userId, { actif });

    const updatedUser = await this.utilisateurRepository.findOne({
      where: { id: userId },
      select: ['id', 'nom', 'prenom', 'email', 'matricule', 'role', 'actif', 'misAJourLe'],
    });

    return updatedUser;
  }

  // Obtenir les statistiques des utilisateurs par statut et rôle
  async getUsersStats() {
    const stats = await this.utilisateurRepository
      .createQueryBuilder('user')
      .select('user.role', 'role')
      .addSelect('user.actif', 'actif')
      .addSelect('COUNT(*)', 'count')
      .groupBy('user.role')
      .addGroupBy('user.actif')
      .getRawMany();

    return stats;
  }

  // Obtenir tous les utilisateurs avec filtres
  async getAllUsersWithFilters(role?: string, actif?: boolean) {
    const queryBuilder = this.utilisateurRepository
      .createQueryBuilder('user')
      .select([
        'user.id',
        'user.nom',
        'user.prenom',
        'user.email',
        'user.telephone',
        'user.matricule',
        'user.role',
        'user.actif',
        'user.creeLe',
        'user.misAJourLe',
      ])
      .orderBy('user.creeLe', 'DESC');

    if (role) {
      queryBuilder.andWhere('user.role = :role', { role });
    }

    if (actif !== undefined) {
      queryBuilder.andWhere('user.actif = :actif', { actif });
    }

    return queryBuilder.getMany();
  }
}