import { Body, Controller, Delete, Get, Param, ParseIntPipe, Post, Put, Req, UseGuards } from '@nestjs/common';
import { TasksService } from './tasks.service';
import { JwtAuthGuard } from '@stm/auth';
import { CreateTaskDto, UpdateTaskDto } from '@stm/data';
import { Request } from 'express';

@Controller('tasks')
@UseGuards(JwtAuthGuard)
export class TasksController {
  constructor(private tasks: TasksService) {}

  @Get()
  list(@Req() req: Request) { return this.tasks.list((req as any).user); }

  @Post()
  create(@Req() req: Request, @Body() body: CreateTaskDto) {
    return this.tasks.create((req as any).user, body);
  }

  @Put(':id')
  update(@Req() req: Request, @Param('id', ParseIntPipe) id: number, @Body() body: UpdateTaskDto) {
    return this.tasks.update((req as any).user, id, body);
  }

  @Delete(':id')
  delete(@Req() req: Request, @Param('id', ParseIntPipe) id: number) {
    return this.tasks.delete((req as any).user, id);
  }
}
