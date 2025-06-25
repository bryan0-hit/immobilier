import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BiensService } from './bien.service';
import { BiensController } from './bien.controller';
import { Bien } from './entities/bien.entity';
import { CloudinaryModule } from 'src/cloudinary/cloudinary.module';

@Module({
  imports: [TypeOrmModule.forFeature([Bien]), CloudinaryModule],
  controllers: [BiensController],
  providers: [BiensService],
  exports: [BiensService]
})
export class BienModule {}