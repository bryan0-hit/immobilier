import { Module } from '@nestjs/common';
import { PaiementService } from './paiement.service';
import { PaiementController } from './paiement.controller';

@Module({
  controllers: [PaiementController],
  providers: [PaiementService],
})
export class PaiementModule {}
