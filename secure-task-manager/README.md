# Secure Task Management System (NX Monorepo)

This repo implements a secure Task Management System with JWT auth and RBAC.
It includes a **NestJS API** and an **Angular dashboard** in an Nx workspace layout.

> Created on 2025-08-27T00:46:00.596443Z

## Monorepo Layout

apps/
  api/         -> NestJS backend
  dashboard/   -> Angular frontend (skeleton, intended to be generated via Nx and ported here)

libs/
  data/        -> Shared TypeScript interfaces & DTOs
  auth/        -> Reusable RBAC logic and decorators

## Features
- JWT authentication (/api/auth/login)
- RBAC (Owner/Admin/Viewer) with org-scoped access
- ...

# secure-task-manager
