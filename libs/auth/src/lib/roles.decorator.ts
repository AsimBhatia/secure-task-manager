import { SetMetadata } from '@nestjs/common';
export const ROLES_KEY='roles';
export const Roles=(...roles: Array<'Owner'|'Admin'|'Viewer'>)=>SetMetadata(ROLES_KEY,roles);
