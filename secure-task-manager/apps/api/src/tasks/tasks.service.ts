import { Injectable, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Task } from '../entities/task.entity';
import { UsersService } from '../users/users.service';
import { OrgsService } from '../orgs/orgs.service';
import { CreateTaskDto, UpdateTaskDto } from '@stm/data';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class TasksService {
  constructor(
    @InjectRepository(Task) private tasksRepo: Repository<Task>,
    private users: UsersService,
    private orgs: OrgsService,
    private audit: AuditService,
  ) {}

  async ensureWriteAccess(user: any, task: Task) {
    const roles: string[] = user.roles ?? [];
    const accessibleOrgIds = await this.orgs.findAccessibleOrgIds(user.orgId);
    const inScope = accessibleOrgIds.includes(task.organization.id);
    if (!inScope) throw new ForbiddenException('Out of org scope');
    if (!(roles.includes('Owner') || roles.includes('Admin') || task.owner.id === user.sub)) {
      throw new ForbiddenException('Insufficient permissions');
    }
  }

  async list(user: any) {
    const accessibleOrgIds = await this.orgs.findAccessibleOrgIds(user.orgId);
    const roles: string[] = user.roles ?? [];
    if (roles.includes('Owner') || roles.includes('Admin')) {
      return this.tasksRepo.find({ where: { organization: { id: accessibleOrgIds } } as any, order: { order: 'ASC' } });
    }
    return this.tasksRepo.find({
      where: [
        { owner: { id: user.sub }, organization: { id: accessibleOrgIds[0] } } as any,
        { assignedTo: { id: user.sub }, organization: { id: accessibleOrgIds[0] } } as any,
      ],
      order: { order: 'ASC' },
    });
  }

  async create(user: any, dto: CreateTaskDto) {
    const owner = await this.users.findById(user.sub);
    const assigned = dto.assignedToId ? await this.users.findById(dto.assignedToId) : null;
    const entity = this.tasksRepo.create({
      title: dto.title,
      description: dto.description,
      category: (dto.category ?? 'Work') as any,
      status: (dto.status ?? 'todo') as any,
      order: dto.order ?? 0,
      owner: owner!,
      organization: owner!.organization,
      assignedTo: assigned ?? null,
    });
    const saved = await this.tasksRepo.save(entity);
    this.audit.log({ actor: user.email, action: 'task:create', id: saved.id });
    return saved;
  }

  async update(user: any, id: number, dto: UpdateTaskDto) {
    const task = await this.tasksRepo.findOne({ where: { id } });
    if (!task) return null;
    await this.ensureWriteAccess(user, task);
    if (dto.title !== undefined) task.title = dto.title;
    if (dto.description !== undefined) task.description = dto.description;
    if (dto.category !== undefined) task.category = dto.category as any;
    if (dto.status !== undefined) task.status = dto.status as any;
    if (dto.order !== undefined) task.order = dto.order;
    if (dto.assignedToId !== undefined) task.assignedTo = dto.assignedToId ? await this.users.findById(dto.assignedToId) : null;
    const saved = await this.tasksRepo.save(task);
    this.audit.log({ actor: user.email, action: 'task:update', id: saved.id });
    return saved;
  }

  async delete(user: any, id: number) {
    const task = await this.tasksRepo.findOne({ where: { id } });
    if (!task) return { affected: 0 };
    await this.ensureWriteAccess(user, task);
    const res = await this.tasksRepo.delete(id);
    this.audit.log({ actor: user.email, action: 'task:delete', id });
    return res;
  }
}
