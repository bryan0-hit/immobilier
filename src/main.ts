import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser()); 
  app.enableCors({
    origin: process.env.CORS_ORIGIN || '*', // Set your CORS origin here
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });
  app.setGlobalPrefix('api'); // Set a global prefix for all routes
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
