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

  // Orgs
  let parent = await orgRepo.findOne({ where: { name: 'Acme Corp' } });
  if (!parent) parent = await orgRepo.save(orgRepo.create({ name: 'Acme Corp' }));

  let child = await orgRepo.findOne({ where: { name: 'Acme East' } });
  if (!child) child = await orgRepo.save(orgRepo.create({ name: 'Acme East', parent }));

  // Roles
  const getRole = async (name: 'Owner'|'Admin'|'Viewer') =>
    (await roleRepo.findOne({ where: { name } })) ??
    (await roleRepo.save(roleRepo.create({ name } as any)));

  const ownerRole = await getRole('Owner');
  const adminRole = await getRole('Admin');
  const viewerRole = await getRole('Viewer');

  // Users
  const upsertUser = async (email: string, name: string, org: Organization, roles: Role[]) => {
    let u = await userRepo.findOne({ where: { email } });
    if (!u) {
      u = userRepo.create({
        email,
        name,
        passwordHash: await bcrypt.hash('password', 10),
        organization: org,
        roles,
      });
    } else {
      u.name = name;
      u.organization = org;
      u.roles = roles;
    }
    return userRepo.save(u);
  };

  const owner = await upsertUser('owner@acme.com', 'Olivia Owner', parent, [ownerRole]);
  const admin = await upsertUser('admin@acme.com', 'Alex Admin', child, [adminRole]);
  const viewer = await upsertUser('viewer@acme.com', 'Violet Viewer', child, [viewerRole]);

  // Tasks (avoid duplicates by title+org)
  const ensureTask = async (title: string, org: Organization, ownerUser: User, extra: Partial<Task> = {}) => {
    let t = await taskRepo.findOne({ where: { title, organization: { id: org.id } } as any });
    if (!t) {
      t = taskRepo.create({ title, organization: org, owner: ownerUser, ...extra });
      t = await taskRepo.save(t);
    }
    return t;
  };

  await ensureTask('Plan Q3 roadmap', parent, owner, { status: 'in-progress' as any });
  await ensureTask('Team standup', child, admin, { status: 'todo' as any, assignedTo: viewer });

  console.log('Seed complete (idempotent).');
  await dataSource.destroy();
}


run().catch(e => { console.error(e); process.exit(1); });
