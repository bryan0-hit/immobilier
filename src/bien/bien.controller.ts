import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  Patch, 
  Param, 
  Delete, 
  Query, 
  UseGuards, 
  Request,
  UseInterceptors,
  UploadedFiles,
  UploadedFile,
  ParseFilePipe,
  MaxFileSizeValidator,
  FileTypeValidator
} from '@nestjs/common';
import { FilesInterceptor, FileInterceptor } from '@nestjs/platform-express';
import { BiensService } from './bien.service';
import { CreateBienDto } from './dto/create-bien.dto';
import { UpdateBienDto } from './dto/update-bien.dto';
import { TransferOwnershipDto } from './dto/transfer-ownership.dto';
import { FilterBienDto } from './dto/filter-bien.dto';
import { PropertyStatus } from 'src/enums/enums';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@Controller('biens')
@UseGuards(JwtAuthGuard)
export class BiensController {
  constructor(private readonly biensService: BiensService) {}

  @Post()
  create(@Body() createBienDto: CreateBienDto, @Request() req) {
    return this.biensService.create(createBienDto, req.user.id);
  }

  @Get()
  findAll(@Query() filterDto: FilterBienDto) {
    return this.biensService.findAll(filterDto);
  }

  @Get('statistics')
  getStatistics() {
    return this.biensService.getStatistics();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.biensService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateBienDto: UpdateBienDto, @Request() req) {
    return this.biensService.update(id, updateBienDto, req.user.id);
  }

  @Patch(':id/transfer-ownership')
  transferOwnership(@Param('id') id: string, @Body() transferDto: TransferOwnershipDto, @Request() req) {
    return this.biensService.transferOwnership(id, transferDto, req.user.id);
  }

  @Patch(':bienId/pieces/:pieceId/status')
  updatePieceStatus(
    @Param('bienId') bienId: string,
    @Param('pieceId') pieceId: string,
    @Body('status') status: PropertyStatus,
    @Request() req
  ) {
    return this.biensService.updatePieceStatus(bienId, pieceId, status, req.user.id);
  }

  // Upload multiple photos pour une pièce (ajouter aux existantes)
  @Post(':bienId/pieces/:pieceId/photos')
  @UseInterceptors(FilesInterceptor('photos', 10)) // Maximum 10 fichiers
  uploadPiecePhotos(
    @Param('bienId') bienId: string,
    @Param('pieceId') pieceId: string,
    @UploadedFiles(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 }), // 5MB max par fichier
          new FileTypeValidator({ fileType: /^image\/(jpeg|jpg|png|webp)$/ })
        ],
      })
    ) files: Express.Multer.File[],
    @Request() req
  ) {
    return this.biensService.uploadPiecePhotos(bienId, pieceId, files, req.user.id);
  }

  // Remplacer toutes les photos d'une pièce
  @Patch(':bienId/pieces/:pieceId/photos')
  @UseInterceptors(FilesInterceptor('photos', 10))
  updatePiecePhotos(
    @Param('bienId') bienId: string,
    @Param('pieceId') pieceId: string,
    @UploadedFiles(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 }), // 5MB max par fichier
          new FileTypeValidator({ fileType: /^image\/(jpeg|jpg|png|webp)$/ })
        ],
      })
    ) files: Express.Multer.File[],
    @Request() req
  ) {
    return this.biensService.updatePiecePhotos(bienId, pieceId, files, req.user.id);
  }

  // Supprimer une photo spécifique d'une pièce
  @Delete(':bienId/pieces/:pieceId/photos')
  deletePiecePhoto(
    @Param('bienId') bienId: string,
    @Param('pieceId') pieceId: string,
    @Body('photoUrl') photoUrl: string,
    @Request() req
  ) {
    return this.biensService.deletePiecePhoto(bienId, pieceId, photoUrl, req.user.id);
  }

  @Delete(':id')
  remove(@Param('id') id: string, @Request() req) {
    return this.biensService.remove(id, req.user.id);
  }
}