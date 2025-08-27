import { Controller, Get, Req, UseGuards, ForbiddenException } from '@nestjs/common';
import { AuditService } from './audit.service';
import { JwtAuthGuard } from '@stm/auth';
import { Request } from 'express';

@Controller('audit-log')
export class AuditController {
  constructor(private audit: AuditService) {}
  @UseGuards(JwtAuthGuard)
  @Get()
  getAudit(@Req() req: Request) {
    const user: any = (req as any).user;
    const roles: string[] = user?.roles ?? [];
    if (!roles.includes('Owner') && !roles.includes('Admin')) throw new ForbiddenException('Not authorized to view audit log');
    return this.audit.read();
  }
}
