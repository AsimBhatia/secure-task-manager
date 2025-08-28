import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from 'typeorm';
import { User } from './user.entity';

@Entity()
export class Role {
  @PrimaryGeneratedColumn() id!: number;
  @Column({ unique: true }) name!: 'Owner' | 'Admin' | 'Viewer';
  @ManyToMany(() => User, (user) => user.roles) users!: User[];
}
