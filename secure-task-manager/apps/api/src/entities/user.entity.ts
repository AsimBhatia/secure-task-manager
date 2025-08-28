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
