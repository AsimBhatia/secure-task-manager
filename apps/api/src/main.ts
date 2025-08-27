import 'reflect-metadata';
import * as dotenv from 'dotenv';
dotenv.config();

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';             // <-- change

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: true });
  app.use(helmet());
  app.use(morgan('dev'));
  app.use(cors());                   // <-- works now
  app.setGlobalPrefix('api');
  await app.listen(3000);
  console.log('API running on http://localhost:3000/api');
}
bootstrap();
