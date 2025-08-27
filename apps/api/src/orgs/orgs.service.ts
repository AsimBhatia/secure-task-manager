import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../entities/organization.entity';

@Injectable()
export class OrgsService {
  constructor(@InjectRepository(Organization) private orgsRepo: Repository<Organization>) {}
  async findAccessibleOrgIds(rootOrgId: number): Promise<number[]> {
    const org = await this.orgsRepo.findOne({ where: { id: rootOrgId }, relations: ['children'] });
    const ids = [rootOrgId];
    if (org?.children) ids.push(...org.children.map(c => c.id));
    return ids;
  }
}
