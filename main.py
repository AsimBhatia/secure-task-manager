# Rebuild the project and FIX the README writing issue by avoiding f-strings entirely.
import os, json, textwrap, zipfile, shutil, datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

root = BASE_DIR / "secure-task-manager"
if os.path.exists(root):
    shutil.rmtree(root)
os.makedirs(root, exist_ok=True)

def w(path, content):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)

# ---- Root files ----
package_json = {
  "name": "secure-task-manager",
  "private": True,
  "version": "0.1.0",
  "packageManager": "npm@10.8.1",
  "scripts": {
    "dev:api": "nx serve api",
    "dev:dashboard": "nx serve dashboard",
    "build:api": "nx build api",
    "build:dashboard": "nx build dashboard",
    "test:api": "nx test api",
    "test:dashboard": "nx test dashboard",
    "seed": "ts-node -r tsconfig-paths/register apps/api/src/seed.ts"
  },
  "devDependencies": {
    "@nx/angular": "^19.5.3",
    "@nx/nest": "^19.5.3",
    "@nx/node": "^19.5.3",
    "@nx/esbuild": "^19.5.3",
    "@nx/jest": "^19.5.3",
    "nx": "^19.5.3",
    "typescript": "^5.5.4",
    "ts-node": "^10.9.2",
    "tsconfig-paths": "^4.2.0",
    "jest": "^29.7.0",
    "@types/jest": "^29.5.13"
  },
  "dependencies": {
    "@nestjs/common": "^10.3.8",
    "@nestjs/core": "^10.3.8",
    "@nestjs/platform-express": "^10.3.8",
    "@nestjs/jwt": "^10.2.0",
    "@nestjs/passport": "^10.0.3",
    "passport": "^0.7.0",
    "passport-jwt": "^4.0.1",
    "bcryptjs": "^2.4.3",
    "class-transformer": "^0.5.1",
    "class-validator": "^0.14.1",
    "dotenv": "^16.4.5",
    "reflect-metadata": "^0.2.2",
    "rxjs": "^7.8.1",
    "typeorm": "^0.3.20",
    "sqlite3": "^5.1.7",
    "pg": "^8.13.0",
    "@nestjs/typeorm": "^10.0.2",
    "express": "^4.19.2",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0",
    "cors": "^2.8.5"
  }
}
w("package.json", json.dumps(package_json, indent=2))

w("nx.json", json.dumps({
  "npmScope": "stm",
  "affected": { "defaultBase": "main" },
  "workspaceLayout": { "appsDir": "apps", "libsDir": "libs" }
}, indent=2))

w("tsconfig.base.json", json.dumps({
  "compileOnSave": False,
  "compilerOptions": {
    "rootDir": ".",
    "baseUrl": ".",
    "outDir": "dist/out-tsc",
    "sourceMap": True,
    "declaration": False,
    "esModuleInterop": True,
    "emitDecoratorMetadata": True,
    "experimentalDecorators": True,
    "moduleResolution": "node",
    "resolveJsonModule": True,
    "target": "ES2022",
    "module": "commonjs",
    "types": ["node"],
    "paths": {
      "@stm/data": ["libs/data/src/index.ts"],
      "@stm/auth": ["libs/auth/src/index.ts"]
    }
  }
}, indent=2))

w(".env.example", "JWT_SECRET=changeme-super-secret\nDB_TYPE=sqlite\nDB_NAME=task_manager.db\n")

# ---- libs/data ----
w("libs/data/src/index.ts", "export * from './lib/dto';\nexport * from './lib/types';\n")
w("libs/data/src/lib/types.ts", textwrap.dedent('''\
export type RoleName = 'Owner' | 'Admin' | 'Viewer';

export interface JwtUserPayload {
  sub: number;
  email: string;
  orgId: number;
  roles: RoleName[];
  permissions: string[];
  iat?: number;
  exp?: number;
}

export type TaskStatus = 'todo' | 'in-progress' | 'done';
export type TaskCategory = 'Work' | 'Personal' | 'Other';
'''))
w("libs/data/src/lib/dto.ts", textwrap.dedent('''\
export interface LoginDto { email: string; password: string; }
export interface CreateTaskDto {
  title: string;
  description?: string;
  category?: 'Work'|'Personal'|'Other';
  status?: 'todo'|'in-progress'|'done';
  order?: number;
  assignedToId?: number | null;
}
export interface UpdateTaskDto extends Partial<CreateTaskDto> {}
'''))
w("libs/data/project.json", json.dumps({
  "name": "data",
  "sourceRoot": "libs/data/src",
  "projectType": "library",
  "targets": {
    "build": {
      "executor": "@nx/js:tsc",
      "options": {
        "outputPath": "dist/libs/data",
        "main": "libs/data/src/index.ts",
        "tsConfig": "libs/data/tsconfig.lib.json"
      }
    }
  }
}, indent=2))
w("libs/data/tsconfig.lib.json", json.dumps({
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "outDir": "../../dist/out-tsc", "declaration": True, "types": [] },
  "include": ["src/**/*.ts"]
}, indent=2))

# ---- libs/auth ----
w("libs/auth/src/index.ts", "export * from './lib/permissions';\nexport * from './lib/roles.decorator';\nexport * from './lib/rbac.guard';\nexport * from './lib/org-scope.guard';\nexport * from './lib/jwt-auth.guard';\n")
w("libs/auth/src/lib/permissions.ts", textwrap.dedent('''\
export const PERMISSIONS = {
  TASK_CREATE: 'task:create',
  TASK_READ: 'task:read',
  TASK_UPDATE: 'task:update',
  TASK_DELETE: 'task:delete',
  AUDIT_READ: 'audit:read',
} as const;

export const ROLE_PERMISSIONS: Record<string, string[]> = {
  Owner: [PERMISSIONS.TASK_CREATE, PERMISSIONS.TASK_READ, PERMISSIONS.TASK_UPDATE, PERMISSIONS.TASK_DELETE, PERMISSIONS.AUDIT_READ],
  Admin: [PERMISSIONS.TASK_CREATE, PERMISSIONS.TASK_READ, PERMISSIONS.TASK_UPDATE, PERMISSIONS.TASK_DELETE, PERMISSIONS.AUDIT_READ],
  Viewer: [PERMISSIONS.TASK_READ],
};
'''))
w("libs/auth/src/lib/roles.decorator.ts", "import { SetMetadata } from '@nestjs/common';\nexport const ROLES_KEY='roles';\nexport const Roles=(...roles: Array<'Owner'|'Admin'|'Viewer'>)=>SetMetadata(ROLES_KEY,roles);\n")
w("libs/auth/src/lib/jwt-auth.guard.ts", textwrap.dedent('''\
import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) { return super.canActivate(context); }
  handleRequest(err: any, user: any) { if (err || !user) throw err || new UnauthorizedException(); return user; }
}
'''))
w("libs/auth/src/lib/rbac.guard.ts", textwrap.dedent('''\
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from './roles.decorator';

@Injectable()
export class RbacGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Array<'Owner'|'Admin'|'Viewer'>>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles || requiredRoles.length === 0) return true;
    const { user } = context.switchToHttp().getRequest();
    if (!user) return false;
    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}
'''))
w("libs/auth/src/lib/org-scope.guard.ts", textwrap.dedent('''\
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

@Injectable()
export class OrgScopeGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    return true; // Controllers/services enforce org scope in this MVP
  }
}
'''))
w("libs/auth/project.json", json.dumps({
  "name": "auth",
  "sourceRoot": "libs/auth/src",
  "projectType": "library",
  "targets": {
    "build": {
      "executor": "@nx/js:tsc",
      "options": {
        "outputPath": "dist/libs/auth",
        "main": "libs/auth/src/index.ts",
        "tsConfig": "libs/auth/tsconfig.lib.json"
      }
    }
  }
}, indent=2))
w("libs/auth/tsconfig.lib.json", json.dumps({
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "outDir": "../../dist/out-tsc", "declaration": True, "types": [] },
  "include": ["src/**/*.ts"]
}, indent=2))

# ---- apps/api (NestJS) ----
w("apps/api/project.json", json.dumps({
  "name": "api",
  "sourceRoot": "apps/api/src",
  "projectType": "application",
  "targets": {
    "build": {
      "executor": "@nx/esbuild:esbuild",
      "options": {
        "main": "apps/api/src/main.ts",
        "outputPath": "dist/apps/api",
        "tsConfig": "apps/api/tsconfig.app.json",
        "external": ["class-transformer","class-validator","reflect-metadata","bcryptjs","sqlite3","pg"]
      }
    },
    "serve": { "executor": "@nx/node:node", "options": { "buildTarget": "api:build" } },
    "test": { "executor": "@nx/jest:jest", "options": { "jestConfig": "apps/api/jest.config.json" } }
  }
}, indent=2))
w("apps/api/tsconfig.app.json", json.dumps({
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "outDir": "../../dist/out-tsc", "types": ["node"] },
  "include": ["src/**/*.ts"]
}, indent=2))
w("apps/api/jest.config.json", json.dumps({
  "preset": "ts-jest",
  "testEnvironment": "node",
  "testMatch": ["**/?(*.)+(spec|test).[jt]s?(x)"]
}, indent=2))
w("apps/api/src/main.ts", textwrap.dedent('''\
import 'reflect-metadata';
import * as dotenv from 'dotenv';
dotenv.config();
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as helmet from 'helmet';
import * as morgan from 'morgan';
import * as cors from 'cors';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: true });
  app.use(helmet.default());
  app.use(morgan('dev'));
  app.use(cors());
  app.setGlobalPrefix('api');
  await app.listen(3000);
  console.log('API running on http://localhost:3000/api');
}
bootstrap();
'''))
w("apps/api/src/app.module.ts", textwrap.dedent('''\
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { OrgsModule } from './orgs/orgs.module';
import { RolesModule } from './roles/roles.module';
import { TasksModule } from './tasks/tasks.module';
import { AuditModule } from './audit/audit.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRootAsync({
      useFactory: () => {
        const type = process.env.DB_TYPE || 'sqlite';
        if (type === 'postgres') {
          return {
            type: 'postgres',
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT || '5432', 10),
            username: process.env.DB_USER || 'postgres',
            password: process.env.DB_PASS || 'postgres',
            database: process.env.DB_NAME || 'task_manager',
            autoLoadEntities: true,
            synchronize: true,
          } as any;
        }
        return {
          type: 'sqlite',
          database: process.env.DB_NAME || 'task_manager.db',
          autoLoadEntities: true,
          synchronize: true,
        } as any;
      },
    }),
    AuthModule,
    UsersModule,
    OrgsModule,
    RolesModule,
    TasksModule,
    AuditModule,
  ],
})
export class AppModule {}
'''))

# Entities
w("apps/api/src/entities/organization.entity.ts", textwrap.dedent('''\
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany } from 'typeorm';

@Entity()
export class Organization {
  @PrimaryGeneratedColumn() id!: number;
  @Column({ unique: true }) name!: string;
  @ManyToOne(() => Organization, (org) => org.children, { nullable: true }) parent?: Organization | null;
  @OneToMany(() => Organization, (org) => org.parent) children!: Organization[];
}
'''))
w("apps/api/src/entities/role.entity.ts", textwrap.dedent('''\
import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from 'typeorm';
import { User } from './user.entity';

@Entity()
export class Role {
  @PrimaryGeneratedColumn() id!: number;
  @Column({ unique: true }) name!: 'Owner' | 'Admin' | 'Viewer';
  @ManyToMany(() => User, (user) => user.roles) users!: User[];
}
'''))
w("apps/api/src/entities/permission.entity.ts", textwrap.dedent('''\
import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';
@Entity()
export class Permission {
  @PrimaryGeneratedColumn() id!: number;
  @Column({ unique: true }) code!: string;
}
'''))
w("apps/api/src/entities/user.entity.ts", textwrap.dedent('''\
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, ManyToMany, JoinTable } from 'typeorm';
import { Organization } from './organization.entity';
import { Role } from './role.entity';

@Entity()
export class User {
  @PrimaryGeneratedColumn() id!: number;
  @Column({ unique: true }) email!: string;
  @Column() name!: string;
  @Column() passwordHash!: string;
  @ManyToOne(() => Organization, { eager: true }) organization!: Organization;
  @ManyToMany(() => Role, { eager: true }) @JoinTable() roles!: Role[];
}
'''))
w("apps/api/src/entities/task.entity.ts", textwrap.dedent('''\
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { User } from './user.entity';
import { Organization } from './organization.entity';

@Entity()
export class Task {
  @PrimaryGeneratedColumn() id!: number;
  @Column() title!: string;
  @Column({ nullable: true }) description?: string;
  @Column({ default: 'Work' }) category!: 'Work'|'Personal'|'Other';
  @Column({ default: 'todo' }) status!: 'todo'|'in-progress'|'done';
  @Column({ default: 0 }) order!: number;
  @ManyToOne(() => User, { eager: true }) owner!: User;
  @ManyToOne(() => User, { nullable: true, eager: true }) assignedTo?: User | null;
  @ManyToOne(() => Organization, { eager: true }) organization!: Organization;
  @CreateDateColumn() createdAt!: Date;
  @UpdateDateColumn() updatedAt!: Date;
}
'''))

# Auth
w("apps/api/src/auth/auth.module.ts", textwrap.dedent('''\
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../entities/user.entity';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    PassportModule,
    JwtModule.register({ secret: process.env.JWT_SECRET || 'changeme', signOptions: { expiresIn: '8h' } }),
  ],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
'''))
w("apps/api/src/auth/auth.service.ts", textwrap.dedent('''\
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
'''))
w("apps/api/src/auth/auth.controller.ts", textwrap.dedent('''\
import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from '@stm/data';

@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService) {}
  @Post('login') login(@Body() body: LoginDto) { return this.auth.login(body.email, body.password); }
}
'''))
w("apps/api/src/auth/jwt.strategy.ts", textwrap.dedent('''\
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtUserPayload } from '@stm/data';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({ jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), ignoreExpiration: false, secretOrKey: process.env.JWT_SECRET || 'changeme' });
  }
  async validate(payload: JwtUserPayload) { return payload; }
}
'''))

# Users/Orgs/Roles Services
w("apps/api/src/users/users.module.ts", "import { Module } from '@nestjs/common';\nimport { TypeOrmModule } from '@nestjs/typeorm';\nimport { User } from '../entities/user.entity';\nimport { UsersService } from './users.service';\n@Module({imports:[TypeOrmModule.forFeature([User])],providers:[UsersService],exports:[UsersService]})\nexport class UsersModule {}\n")
w("apps/api/src/users/users.service.ts", "import { Injectable } from '@nestjs/common';\nimport { InjectRepository } from '@nestjs/typeorm';\nimport { Repository } from 'typeorm';\nimport { User } from '../entities/user.entity';\n@Injectable()\nexport class UsersService{constructor(@InjectRepository(User) private usersRepo:Repository<User>){}\nfindById(id:number){return this.usersRepo.findOne({where:{id}})} }\n")
w("apps/api/src/orgs/orgs.module.ts", "import { Module } from '@nestjs/common';\nimport { TypeOrmModule } from '@nestjs/typeorm';\nimport { Organization } from '../entities/organization.entity';\nimport { OrgsService } from './orgs.service';\n@Module({imports:[TypeOrmModule.forFeature([Organization])],providers:[OrgsService],exports:[OrgsService]})\nexport class OrgsModule {}\n")
w("apps/api/src/orgs/orgs.service.ts", textwrap.dedent('''\
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
'''))
w("apps/api/src/roles/roles.module.ts", "import { Module } from '@nestjs/common';\nimport { TypeOrmModule } from '@nestjs/typeorm';\nimport { Role } from '../entities/role.entity';\nimport { RolesService } from './roles.service';\n@Module({imports:[TypeOrmModule.forFeature([Role])],providers:[RolesService],exports:[RolesService]})\nexport class RolesModule {}\n")
w("apps/api/src/roles/roles.service.ts", "import { Injectable } from '@nestjs/common';\nimport { InjectRepository } from '@nestjs/typeorm';\nimport { Repository } from 'typeorm';\nimport { Role } from '../entities/role.entity';\n@Injectable()\nexport class RolesService{constructor(@InjectRepository(Role) private rolesRepo:Repository<Role>){}\nfindByName(name:'Owner'|'Admin'|'Viewer'){return this.rolesRepo.findOne({where:{name}})} }\n")

# Audit
w("apps/api/src/audit/audit.module.ts", "import { Module } from '@nestjs/common';\nimport { AuditService } from './audit.service';\nimport { AuditController } from './audit.controller';\n@Module({providers:[AuditService],controllers:[AuditController],exports:[AuditService]})\nexport class AuditModule {}\n")
w("apps/api/src/audit/audit.service.ts", textwrap.dedent('''\
import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class AuditService {
  private logFile = path.join(process.cwd(), 'audit.log');
  log(entry: Record<string, any>) { const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }); fs.appendFileSync(this.logFile, line+'\\n','utf-8'); }
  read() { if (!fs.existsSync(this.logFile)) return []; return fs.readFileSync(this.logFile,'utf-8').trim().split('\\n').filter(Boolean).map(l=>JSON.parse(l)); }
}
'''))
w("apps/api/src/audit/audit.controller.ts", textwrap.dedent('''\
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
'''))

# Tasks
w("apps/api/src/tasks/tasks.module.ts", textwrap.dedent('''\
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Task } from '../entities/task.entity';
import { TasksService } from './tasks.service';
import { TasksController } from './tasks.controller';
import { UsersModule } from '../users/users.module';
import { OrgsModule } from '../orgs/orgs.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [TypeOrmModule.forFeature([Task]), UsersModule, OrgsModule, AuditModule],
  providers: [TasksService],
  controllers: [TasksController],
})
export class TasksModule {}
'''))
w("apps/api/src/tasks/tasks.service.ts", textwrap.dedent('''\
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
'''))
w("apps/api/src/tasks/tasks.controller.ts", textwrap.dedent('''\
import { Body, Controller, Delete, Get, Param, ParseIntPipe, Post, Put, Req, UseGuards } from '@nestjs/common';
import { TasksService } from './tasks.service';
import { JwtAuthGuard } from '@stm/auth';
import { CreateTaskDto, UpdateTaskDto } from '@stm/data';
import { Request } from 'express';

@Controller('tasks')
@UseGuards(JwtAuthGuard)
export class TasksController {
  constructor(private tasks: TasksService) {}

  @Get()
  list(@Req() req: Request) { return this.tasks.list((req as any).user); }

  @Post()
  create(@Req() req: Request, @Body() body: CreateTaskDto) {
    return this.tasks.create((req as any).user, body);
  }

  @Put(':id')
  update(@Req() req: Request, @Param('id', ParseIntPipe) id: number, @Body() body: UpdateTaskDto) {
    return this.tasks.update((req as any).user, id, body);
  }

  @Delete(':id')
  delete(@Req() req: Request, @Param('id', ParseIntPipe) id: number) {
    return this.tasks.delete((req as any).user, id);
  }
}
'''))

# Seed script
w("apps/api/src/seed.ts", textwrap.dedent('''\
import 'reflect-metadata';
import * as dotenv from 'dotenv';
dotenv.config();
import { DataSource } from 'typeorm';
import { Organization } from './entities/organization.entity';
import { Role } from './entities/role.entity';
import { User } from './entities/user.entity';
import { Task } from './entities/task.entity';
import * as bcrypt from 'bcryptjs';

const type = process.env.DB_TYPE || 'sqlite';
const dataSource = new DataSource(type === 'postgres' ? {
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || 'postgres',
  database: process.env.DB_NAME || 'task_manager',
  synchronize: true,
  entities: [Organization, Role, User, Task],
} as any : {
  type: 'sqlite',
  database: process.env.DB_NAME || 'task_manager.db',
  synchronize: true,
  entities: [Organization, Role, User, Task],
} as any);

async function run() {
  await dataSource.initialize();
  const orgRepo = dataSource.getRepository(Organization);
  const roleRepo = dataSource.getRepository(Role);
  const userRepo = dataSource.getRepository(User);
  const taskRepo = dataSource.getRepository(Task);

  const parent = await orgRepo.save(orgRepo.create({ name: 'Acme Corp' }));
  const child = await orgRepo.save(orgRepo.create({ name: 'Acme East', parent }));

  const ownerRole = await roleRepo.save(roleRepo.create({ name: 'Owner' as any }));
  const adminRole = await roleRepo.save(roleRepo.create({ name: 'Admin' as any }));
  const viewerRole = await roleRepo.save(roleRepo.create({ name: 'Viewer' as any }));

  const owner = userRepo.create({
    email: 'owner@acme.com',
    name: 'Olivia Owner',
    passwordHash: await bcrypt.hash('password', 10),
    organization: parent,
    roles: [ownerRole],
  });
  const admin = userRepo.create({
    email: 'admin@acme.com',
    name: 'Alex Admin',
    passwordHash: await bcrypt.hash('password', 10),
    organization: child,
    roles: [adminRole],
  });
  const viewer = userRepo.create({
    email: 'viewer@acme.com',
    name: 'Violet Viewer',
    passwordHash: await bcrypt.hash('password', 10),
    organization: child,
    roles: [viewerRole],
  });
  await userRepo.save([owner, admin, viewer]);

  await taskRepo.save(taskRepo.create({ title: 'Plan Q3 roadmap', owner, organization: parent, status: 'in-progress' }));
  await taskRepo.save(taskRepo.create({ title: 'Team standup', owner: admin, organization: child, status: 'todo', assignedTo: viewer }));

  console.log('Seed complete.');
  await dataSource.destroy();
}

run().catch(e => { console.error(e); process.exit(1); });
'''))

# ---- apps/dashboard placeholder ----
w("apps/dashboard/project.json", json.dumps({
  "name": "dashboard",
  "sourceRoot": "apps/dashboard/src",
  "projectType": "application",
  "targets": {
    "build": {
      "executor": "@nx/angular:build",
      "options": {
        "outputPath": "dist/apps/dashboard",
        "index": "apps/dashboard/src/index.html",
        "main": "apps/dashboard/src/main.ts",
        "polyfills": ["zone.js"],
        "tsConfig": "apps/dashboard/tsconfig.app.json",
        "assets": ["apps/dashboard/src/favicon.ico","apps/dashboard/src/assets"],
        "styles": ["apps/dashboard/src/styles.css"]
      }
    },
    "serve": { "executor": "@nx/angular:serve", "options": { "buildTarget": "dashboard:build" } },
    "test": { "executor": "@nx/jest:jest", "options": { "jestConfig": "apps/dashboard/jest.config.json" } }
  }
}, indent=2))
w("apps/dashboard/tsconfig.app.json", json.dumps({
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "outDir": "../../dist/out-tsc", "types": ["node"] },
  "files": [],
  "include": ["src/**/*.ts"]
}, indent=2))
w("apps/dashboard/jest.config.json", json.dumps({
  "preset": "jest-preset-angular",
  "setupFilesAfterEnv": ["<rootDir>/setup-jest.ts"],
  "testMatch": ["**/?(*.)+(spec|test).[jt]s?(x)"]
}, indent=2))
w("apps/dashboard/src/index.html", "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Secure Task Manager</title><base href='/'><meta name='viewport' content='width=device-width, initial-scale=1'></head><body><app-root>Loading...</app-root></body></html>")
w("apps/dashboard/src/main.ts", "import './polyfills';\nconsole.log('Angular dashboard placeholder. Generate via Nx and port these files.');\n")
w("apps/dashboard/src/polyfills.ts", "// placeholder for zone.js polyfill\n")
w("apps/dashboard/src/styles.css", "body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,'Noto Sans','Helvetica Neue',Arial,'Apple Color Emoji','Segoe UI Emoji';margin:0} .container{max-width:960px;margin:2rem auto;padding:0 1rem} .card{border:1px solid #e5e7eb;border-radius:12px;padding:1rem;margin-bottom:1rem} .button{padding:.5rem 1rem;border-radius:8px;border:1px solid #e5e7eb;cursor:pointer} .input{padding:.5rem;border-radius:8px;border:1px solid #e5e7eb;width:100%} .row{display:flex;gap:.5rem;align-items:center}")
w("apps/dashboard/src/app/api.ts", textwrap.dedent('''\
export const API_BASE = (localStorage.getItem('API_BASE') || 'http://localhost:3000/api').replace(/\\/$/, '');

export async function apiLogin(email: string, password: string) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error('Login failed');
  return res.json();
}

export async function apiGetTasks() {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/tasks`, { headers: { 'Authorization': `Bearer ${token}` } });
  if (!res.ok) throw new Error('Failed to load tasks');
  return res.json();
}

export async function apiCreateTask(payload: any) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/tasks`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Failed to create task');
  return res.json();
}

export async function apiUpdateTask(id: number, payload: any) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/tasks/${id}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Failed to update task');
  return res.json();
}

export async function apiDeleteTask(id: number) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/tasks/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } });
  if (!res.ok) throw new Error('Failed to delete task');
  return res.json();
}
'''))
w("apps/dashboard/src/app/mock-ui.md", textwrap.dedent('''\
# Angular UI Sketch (to be ported into a generated Angular app)

- Login form (email/password) stores token in localStorage.
- Tasks page:
  - List tasks with drag & drop (Angular CDK) to reorder; patch `order` via API.
  - Create/edit task modal with `title`, `description`, `category`, `status`.
  - Filter/sort by status, category.
  - Show owner/assignee.
- Nav bar: dark/light toggle (CSS class), Logout button.
'''))

created_ts = datetime.datetime.utcnow().isoformat() + "Z"

readme_text = '''# Secure Task Management System (NX Monorepo)

This repo implements a secure Task Management System with JWT auth and RBAC.
It includes a **NestJS API** and an **Angular dashboard** in an Nx workspace layout.

> Created on {ts}

## Monorepo Layout

apps/
  api/         -> NestJS backend
  dashboard/   -> Angular frontend (skeleton, intended to be generated via Nx and ported here)

libs/
  data/        -> Shared TypeScript interfaces & DTOs
  auth/        -> Reusable RBAC logic and decorators

## Features
- JWT authentication (/api/auth/login)
- RBAC (Owner/Admin/Viewer) with org-scoped access
- ...

'''.replace('{ts}', created_ts)

w("README.md", readme_text)