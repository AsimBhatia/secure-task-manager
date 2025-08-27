import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class AuditService {
  private logFile = path.join(process.cwd(), 'audit.log');
  log(entry: Record<string, any>) { const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }); fs.appendFileSync(this.logFile, line+'\n','utf-8'); }
  read() { if (!fs.existsSync(this.logFile)) return []; return fs.readFileSync(this.logFile,'utf-8').trim().split('\n').filter(Boolean).map(l=>JSON.parse(l)); }
}
