export const API_BASE = (localStorage.getItem('API_BASE') || 'http://localhost:3000/api').replace(/\/$/, '');

export async function apiLogin(email: string, password: string) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error('Login failed');
  return res.json();
}

export async function apiGetTasks() {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/tasks`, { headers: { 'Authorization': `Bearer ${token}` } });
  if (!res.ok) throw new Error('Failed to load tasks');
  return res.json();
}

export async function apiCreateTask(payload: any) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/tasks`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Failed to create task');
  return res.json();
}

export async function apiUpdateTask(id: number, payload: any) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/tasks/${id}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Failed to update task');
  return res.json();
}

export async function apiDeleteTask(id: number) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/tasks/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } });
  if (!res.ok) throw new Error('Failed to delete task');
  return res.json();
}
