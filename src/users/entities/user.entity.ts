import { Permission, PermissionType } from 'src/iam/authorization/permission.type';
import { Column, Entity, JoinTable, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { ApiKey } from '../api-keys/entities/api-key.entity/api-key.entity';
import { Role } from '../enums/role.enum';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ enum: Role, default: Role.Regular })
  role: Role;

  @JoinTable()
  @OneToMany((type) => ApiKey, (apiKey) => apiKey.user)
  apiKeys: ApiKey[]

  @Column({ enum: Permission, default: [], type: 'json' })
  permissions: PermissionType[];
}
