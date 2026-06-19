# PlanAssist Backend Development Rules

## System Context
- This repository handles the backend API (`server.js`) and database structure (`schema.sql`).
- This platform serves a live production environment.

## Git & Workflow Rules
- ALWAYS pull context directly from the repository. Do not ask the user to manually upload files.
- NEVER overwrite or rewrite a full code file. Only modify targeted blocks, functions, or specific lines.
- DEFAULT BRANCH: All development tasks must be committed to the `staging` branch. 
- When a task is complete, commit the changes to `staging` and open a Pull Request from `staging` into `main`. Do not create random feature branches.
- AUTOMATED CLEANUP: Immediately after a Pull Request is successfully merged into `main`, you must automatically switch back to the `staging` branch and pull/merge the updated `main` branch back into `staging`. Never leave `staging` behind `main`.

## Architectural Constraints
- **Database edits (`schema.sql`)**: All modifications must be safe to execute directly over the live production database. Utilize conditional drops, catches, or clauses (e.g., `IF EXISTS`, `IF NOT EXISTS`, `DROP TABLE IF EXISTS`) to ensure no existing user data is wiped or corrupted during migrations.
