import { Test, TestingModule } from '@nestjs/testing';
import { BienService } from './bien.service';

describe('BienService', () => {
  let service: BienService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [BienService],
    }).compile();

    service = module.get<BienService>(BienService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
