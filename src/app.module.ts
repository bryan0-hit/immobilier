import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { BienModule } from './bien/bien.module';
import { LocationModule } from './location/location.module';
import { PaiementModule } from './paiement/paiement.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';

@Module({  
  imports: [
    // Config globale
    ConfigModule.forRoot({ 
      isGlobal: true, 
      envFilePath: '.env' 
    }),
    TypeOrmModule.forRootAsync({ 
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get<string>('DATABASE_URL'),
        entities: [__dirname + "/**/*.entity{.ts,.js}"],
        synchronize: true, // À désactiver en production
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    BienModule,
    LocationModule,
    UsersModule,
    PaiementModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
