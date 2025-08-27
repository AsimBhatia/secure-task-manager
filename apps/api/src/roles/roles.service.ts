import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Role } from '../entities/role.entity';
@Injectable()
export class RolesService{constructor(@InjectRepository(Role) private rolesRepo:Repository<Role>){}
findByName(name:'Owner'|'Admin'|'Viewer'){return this.rolesRepo.findOne({where:{name}})} }
