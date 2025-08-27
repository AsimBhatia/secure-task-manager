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
