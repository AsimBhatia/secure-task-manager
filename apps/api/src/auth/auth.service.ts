import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { User } from '../entities/user.entity';
import * as bcrypt from 'bcryptjs';
import { ROLE_PERMISSIONS } from '@stm/auth';
import { JwtUserPayload } from '@stm/data';

@Injectable()
export class AuthService {
  constructor(@InjectRepository(User) private usersRepo: Repository<User>, private jwt: JwtService) {}

  async validateUser(email: string, password: string) {
    const user = await this.usersRepo.findOne({ where: { email } });
    if (!user) throw new UnauthorizedException('Invalid credentials');
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) throw new UnauthorizedException('Invalid credentials');
    return user;
  }

  async login(email: string, password: string) {
    const user = await this.validateUser(email, password);
    const roles = user.roles.map(r => r.name);
    const permissions = roles.flatMap(r => ROLE_PERMISSIONS[r] ?? []);
    const payload: JwtUserPayload = { sub: user.id, email: user.email, orgId: user.organization.id, roles: roles as any, permissions };
    const token = await this.jwt.signAsync(payload);
    return { token, user: { id: user.id, email: user.email, name: user.name, roles, orgId: user.organization.id } };
  }
}
