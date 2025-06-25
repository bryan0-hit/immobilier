import { Injectable, NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Bien } from './entities/bien.entity';
import { CreateBienDto } from './dto/create-bien.dto';
import { UpdateBienDto } from './dto/update-bien.dto';
import { TransferOwnershipDto } from './dto/transfer-ownership.dto';
import { FilterBienDto } from './dto/filter-bien.dto';
import { PropertyStatus } from 'src/enums/enums';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class BiensService {
  constructor(
    @InjectRepository(Bien)
    private bienRepository: Repository<Bien>,
    private cloudinaryService: CloudinaryService,
  ) {}

  async create(createBienDto: CreateBienDto, gestionnaireId: string): Promise<Bien> {
    // Si aucun propriétaire spécifié, le gestionnaire devient propriétaire
    const proprietaireId = createBienDto.proprietaireId || gestionnaireId;

    // Générer automatiquement les pièces si non fournies
    let pieces = createBienDto.pieces || [];
    
    if (pieces.length === 0) {
      // Créer des pièces par défaut
      pieces = Array.from({ length: createBienDto.nombredepiece }, (_, index) => ({
        id: uuidv4(),
        nom: `Pièce ${index + 1}`,
        type: 'chambre',
        photos: [],
        loyerMensuel: 0,
        statut: PropertyStatus.DISPONIBLE,
        description: `Pièce ${index + 1} - À configurer`
      }));
    } else {
      // Vérifier que le nombre de pièces correspond
      if (pieces.length !== createBienDto.nombredepiece) {
        throw new BadRequestException(
          `Le nombre de pièces décrites (${pieces.length}) doit correspondre au nombre de pièces spécifié (${createBienDto.nombredepiece})`
        );
      }
      
      // Ajouter des IDs uniques aux pièces
      pieces = pieces.map(piece => ({
        ...piece,
        id: uuidv4()
      }));
    }

    const bien = this.bienRepository.create({
      ...createBienDto,
      proprietaireId,
      pieces,
      charges: createBienDto.charges || 0
    });

    return await this.bienRepository.save(bien);
  }

  async uploadPiecePhotos(bienId: string, pieceId: string, files: Express.Multer.File[], userId: string): Promise<Bien> {
    const bien = await this.findOne(bienId);
    
    // Vérifier que l'utilisateur est le propriétaire
    if (bien.proprietaireId !== userId) {
      throw new ForbiddenException('Vous n\'êtes pas autorisé à modifier ce bien');
    }

    const piece = bien.pieces.find(p => p.id === pieceId);
    if (!piece) {
      throw new NotFoundException(`Pièce avec l'ID ${pieceId} non trouvée`);
    }

    // Upload des images vers Cloudinary
    const uploadedUrls = await this.cloudinaryService.uploadMultipleImages(
      files, 
      `biens/${bienId}/pieces/${pieceId}`
    );

    // Ajouter les nouvelles URLs aux photos existantes
    piece.photos = [...piece.photos, ...uploadedUrls];
    
    return await this.bienRepository.save(bien);
  }

  async deletePiecePhoto(bienId: string, pieceId: string, photoUrl: string, userId: string): Promise<Bien> {
    const bien = await this.findOne(bienId);
    
    // Vérifier que l'utilisateur est le propriétaire
    if (bien.proprietaireId !== userId) {
      throw new ForbiddenException('Vous n\'êtes pas autorisé à modifier ce bien');
    }

    const piece = bien.pieces.find(p => p.id === pieceId);
    if (!piece) {
      throw new NotFoundException(`Pièce avec l'ID ${pieceId} non trouvée`);
    }

    // Supprimer la photo de Cloudinary
    const publicId = this.cloudinaryService.extractPublicId(photoUrl);
    await this.cloudinaryService.deleteImage(publicId);

    // Retirer l'URL de la liste des photos
    piece.photos = piece.photos.filter(photo => photo !== photoUrl);
    
    return await this.bienRepository.save(bien);
  }

  async updatePiecePhotos(bienId: string, pieceId: string, files: Express.Multer.File[], userId: string): Promise<Bien> {
    const bien = await this.findOne(bienId);
    
    // Vérifier que l'utilisateur est le propriétaire
    if (bien.proprietaireId !== userId) {
      throw new ForbiddenException('Vous n\'êtes pas autorisé à modifier ce bien');
    }

    const piece = bien.pieces.find(p => p.id === pieceId);
    if (!piece) {
      throw new NotFoundException(`Pièce avec l'ID ${pieceId} non trouvée`);
    }

    // Supprimer les anciennes photos de Cloudinary
    for (const photoUrl of piece.photos) {
      const publicId = this.cloudinaryService.extractPublicId(photoUrl);
      await this.cloudinaryService.deleteImage(publicId);
    }

    // Upload des nouvelles images
    const uploadedUrls = await this.cloudinaryService.uploadMultipleImages(
      files, 
      `biens/${bienId}/pieces/${pieceId}`
    );

    // Remplacer les photos
    piece.photos = uploadedUrls;
    
    return await this.bienRepository.save(bien);
  }

  async findAll(filterDto?: FilterBienDto): Promise<Bien[]> {
    const query = this.bienRepository.createQueryBuilder('bien')
      .leftJoinAndSelect('bien.proprietaire', 'proprietaire');

    if (filterDto?.statut) {
      // Filtrer par statut des pièces
      query.where(`EXISTS (
        SELECT 1 FROM jsonb_array_elements(bien.pieces) as piece 
        WHERE piece->>'statut' = :statut
      )`, { statut: filterDto.statut });
    }

    if (filterDto?.ville) {
      query.andWhere('bien.ville ILIKE :ville', { ville: `%${filterDto.ville}%` });
    }

    if (filterDto?.proprietaireId) {
      query.andWhere('bien.proprietaireId = :proprietaireId', { 
        proprietaireId: filterDto.proprietaireId 
      });
    }

    return await query.getMany();
  }

  async findOne(id: string): Promise<Bien> {
    const bien = await this.bienRepository.findOne({
      where: { id },
      relations: ['proprietaire']
    });

    if (!bien) {
      throw new NotFoundException(`Bien avec l'ID ${id} non trouvé`);
    }

    return bien;
  }

  async update(id: string, updateBienDto: UpdateBienDto, userId: string): Promise<Bien> {
    const bien = await this.findOne(id);
    
    // Vérifier que l'utilisateur est le propriétaire
    if (bien.proprietaireId !== userId) {
      throw new ForbiddenException('Vous n\'êtes pas autorisé à modifier ce bien');
    }

    // Si le nombre de pièces change, ajuster les pièces
    if (updateBienDto.nombredepiece && updateBienDto.nombredepiece !== bien.nombredepiece) {
      const currentPieces = bien.pieces || [];
      const newCount = updateBienDto.nombredepiece;
      
      if (newCount > currentPieces.length) {
        // Ajouter des pièces
        const additionalPieces = Array.from(
          { length: newCount - currentPieces.length }, 
          (_, index) => ({
            id: uuidv4(),
            nom: `Pièce ${currentPieces.length + index + 1}`,
            type: 'chambre',
            photos: [],
            loyerMensuel: 0,
            statut: PropertyStatus.DISPONIBLE,
            description: `Nouvelle pièce ${currentPieces.length + index + 1}`
          })
        );
        updateBienDto.pieces = [...currentPieces, ...additionalPieces];
      } else if (newCount < currentPieces.length) {
        // Retirer des pièces (garder les premières) et supprimer leurs photos
        const piecesToRemove = currentPieces.slice(newCount);
        for (const piece of piecesToRemove) {
          for (const photoUrl of piece.photos) {
            const publicId = this.cloudinaryService.extractPublicId(photoUrl);
            await this.cloudinaryService.deleteImage(publicId);
          }
        }
        updateBienDto.pieces = currentPieces.slice(0, newCount);
      }
    }

    Object.assign(bien, updateBienDto);
    return await this.bienRepository.save(bien);
  }

  async transferOwnership(id: string, transferDto: TransferOwnershipDto, currentUserId: string): Promise<Bien> {
    const bien = await this.findOne(id);
    
    // Vérifier que l'utilisateur actuel est le propriétaire
    if (bien.proprietaireId !== currentUserId) {
      throw new ForbiddenException('Vous n\'êtes pas autorisé à transférer ce bien');
    }

    bien.proprietaireId = transferDto.nouveauProprietaireId;
    return await this.bienRepository.save(bien);
  }

  async updatePieceStatus(bienId: string, pieceId: string, newStatus: PropertyStatus, userId: string): Promise<Bien> {
    const bien = await this.findOne(bienId);
    
    // Vérifier que l'utilisateur est le propriétaire
    if (bien.proprietaireId !== userId) {
      throw new ForbiddenException('Vous n\'êtes pas autorisé à modifier ce bien');
    }

    const piece = bien.pieces.find(p => p.id === pieceId);
    if (!piece) {
      throw new NotFoundException(`Pièce avec l'ID ${pieceId} non trouvée`);
    }

    // Mettre à jour le statut de la pièce
    piece.statut = newStatus;
    
    return await this.bienRepository.save(bien);
  }

  async getStatistics(): Promise<{
    total: number;
    parStatut: Record<PropertyStatus, number>;
    parVille: Record<string, number>;
  }> {
    const biens = await this.bienRepository.find();
    
    const stats = {
      total: 0,
      parStatut: {
        [PropertyStatus.DISPONIBLE]: 0,
        [PropertyStatus.OCCUPE]: 0,
        [PropertyStatus.EN_TRAVAUX]: 0,
        [PropertyStatus.INDISPONIBLE]: 0
      },
      parVille: {} as Record<string, number>
    };

    biens.forEach(bien => {
      // Compter toutes les pièces
      bien.pieces.forEach(piece => {
        stats.total++;
        stats.parStatut[piece.statut]++;
      });

      // Compter par ville
      if (bien.ville) {
        stats.parVille[bien.ville] = (stats.parVille[bien.ville] || 0) + bien.pieces.length;
      }
    });

    return stats;
  }

  async remove(id: string, userId: string): Promise<void> {
    const bien = await this.findOne(id);
    
    // Vérifier que l'utilisateur est le propriétaire
    if (bien.proprietaireId !== userId) {
      throw new ForbiddenException('Vous n\'êtes pas autorisé à supprimer ce bien');
    }

    // Supprimer toutes les photos des pièces de Cloudinary
    for (const piece of bien.pieces) {
      for (const photoUrl of piece.photos) {
        const publicId = this.cloudinaryService.extractPublicId(photoUrl);
        await this.cloudinaryService.deleteImage(publicId);
      }
    }

    await this.bienRepository.remove(bien);
  }
}