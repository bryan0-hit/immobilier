import { IsEnum, IsOptional, IsString } from "class-validator";
import { PropertyStatus } from "src/enums/enums";



export class FilterBienDto {
  @IsOptional()
  @IsEnum(PropertyStatus)
  statut?: PropertyStatus;

  @IsOptional()
  @IsString()
  ville?: string;

  @IsOptional()
  @IsString()
  proprietaireId?: string;
}