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
