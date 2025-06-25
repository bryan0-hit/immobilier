import { Test, TestingModule } from '@nestjs/testing';
import { BienController } from './bien.controller';
import { BienService } from './bien.service';

describe('BienController', () => {
  let controller: BienController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [BienController],
      providers: [BienService],
    }).compile();

    controller = module.get<BienController>(BienController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
