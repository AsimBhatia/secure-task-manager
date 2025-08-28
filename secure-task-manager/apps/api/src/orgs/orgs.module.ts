import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Organization } from '../entities/organization.entity';
import { OrgsService } from './orgs.service';
@Module({imports:[TypeOrmModule.forFeature([Organization])],providers:[OrgsService],exports:[OrgsService]})
export class OrgsModule {}
