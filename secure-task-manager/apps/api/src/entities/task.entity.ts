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
