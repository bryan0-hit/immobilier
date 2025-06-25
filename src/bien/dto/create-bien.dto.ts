import { IsString, IsOptional, IsNumber, IsArray, ValidateNested, IsNotEmpty, Min, IsEnum } from 'class-validator';
import { Type } from 'class-transformer';
import { PropertyStatus } from 'src/enums/enums';

export class PieceDto {
  @IsString()
  @IsNotEmpty()
  nom: string;

  @IsString()
  @IsNotEmpty()
  type: string;

  @IsArray()
  @IsString({ each: true })
  photos: string[];

  @IsNumber()
  @Min(0)
  loyerMensuel: number;

  @IsEnum(PropertyStatus)
  statut: PropertyStatus;

  @IsOptional()
  @IsString()
  description?: string;
}

export class CreateBienDto {
  @IsString()
  @IsNotEmpty()
  adresse: string;

  @IsOptional()
  @IsString()
  ville?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsNumber()
  @Min(0)
  surface?: number;

  @IsNumber()
  @Min(1)
  nombredepiece: number;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PieceDto)
  pieces?: PieceDto[];

  @IsOptional()
  @IsNumber()
  @Min(0)
  charges?: number;

  @IsOptional()
  @IsString()
  proprietaireId?: string; // Optionnel - si non fourni, le gestionnaire devient propriétaire
}