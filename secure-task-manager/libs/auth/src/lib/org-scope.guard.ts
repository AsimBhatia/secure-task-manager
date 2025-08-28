import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

@Injectable()
export class OrgScopeGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    return true; // Controllers/services enforce org scope in this MVP
  }
}
