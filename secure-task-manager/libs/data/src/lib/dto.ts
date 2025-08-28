export interface LoginDto { email: string; password: string; }
export interface CreateTaskDto {
  title: string;
  description?: string;
  category?: 'Work'|'Personal'|'Other';
  status?: 'todo'|'in-progress'|'done';
  order?: number;
  assignedToId?: number | null;
}
export interface UpdateTaskDto extends Partial<CreateTaskDto> {}
