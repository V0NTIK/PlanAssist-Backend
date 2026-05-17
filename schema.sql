-- ============================================================================
-- PlanAssist - COMPLETELY REDESIGNED Database Schema
-- Major Changes:
-- 1. New tasks table with title/segment system (replacing parent_task_id/split_task_id)
-- 2. New tasks_completed table (replacing completion_history)
-- 3. Removed partial_completions table (integrated into tasks.accumulated_time)
-- 4. Fixed SERIAL IDs to be permanent across all tables
-- ============================================================================

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    grade VARCHAR(10),
    canvas_api_token TEXT,                      -- Encrypted Canvas API token (replaces canvas_url)
    canvas_api_token_iv TEXT,                   -- Initialization vector for token encryption
    present_periods VARCHAR(10) DEFAULT '2-6',
    is_new_user BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Migration: Add API token columns if upgrading from ICS system
ALTER TABLE users ADD COLUMN IF NOT EXISTS canvas_api_token TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS canvas_api_token_iv TEXT;

-- NEW Tasks table - Completely redesigned with title/segment system
CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,                      -- Permanent unique ID for each task/segment
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,                -- Base task name (never changes, acts like old parent_id)
    segment VARCHAR(500),                       -- NULL for base tasks, "Part 1" or "Hypothesis - First Phase" for splits
    class VARCHAR(200) NOT NULL,                -- Course name from Canvas API
    description TEXT,                           -- From assignment.description in Canvas API (HTML formatted)
    url TEXT NOT NULL,                          -- Direct assignment URL from Canvas API
    deadline_date DATE NOT NULL,                -- From assignment.due_at (date part)
    deadline_time TIME,                         -- From assignment.due_at (time part, NULL if date-only)
    estimated_time INTEGER NOT NULL,            -- AI-calculated estimate (minutes)
    user_estimated_time INTEGER,                -- User override (NULL if not set)
    accumulated_time INTEGER DEFAULT 0,         -- Replaces partial_completions table
    completed BOOLEAN DEFAULT FALSE,            -- When TRUE, moves to tasks_completed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    priority_order INTEGER,                     -- Manual priority override (NULL by default)
    is_new BOOLEAN DEFAULT FALSE,               -- Marks newly imported tasks
    deleted BOOLEAN DEFAULT FALSE,              -- Marks tasks as deleted/checked off without removing from database
    -- NEW CANVAS API FIELDS
    course_id BIGINT,                           -- Canvas course ID
    assignment_id BIGINT,                       -- Canvas assignment ID (unique identifier)
    points_possible DECIMAL(10,2),              -- Maximum points for assignment
    assignment_group_id BIGINT,                 -- Category ID (Homework, Exams, etc.)
    current_score DECIMAL(10,2),                -- Student's current score
    current_grade VARCHAR(10),                  -- Student's current grade (letter/percent)
    grading_type VARCHAR(20),                   -- How it's graded (points, percent, pass_fail, etc.)
    unlock_at TIMESTAMP,                        -- When assignment becomes available
    lock_at TIMESTAMP,                          -- When assignment locks
    submitted_at TIMESTAMP,                     -- When student submitted
    is_missing BOOLEAN DEFAULT false,           -- Canvas missing flag
    is_late BOOLEAN DEFAULT false,              -- Canvas late flag
    UNIQUE(user_id, assignment_id)              -- Prevent duplicate assignments per user
);

-- Migration: Add new Canvas API columns to existing tasks table
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS course_id BIGINT;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS assignment_id BIGINT;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS points_possible DECIMAL(10,2);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS assignment_group_id BIGINT;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS current_score DECIMAL(10,2);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS current_grade VARCHAR(10);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS grading_type VARCHAR(20);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS unlock_at TIMESTAMP;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS lock_at TIMESTAMP;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMP;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS is_missing BOOLEAN DEFAULT false;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS is_late BOOLEAN DEFAULT false;

-- Schedules table - Fixed SERIAL ID
CREATE TABLE IF NOT EXISTS schedules (
    id SERIAL PRIMARY KEY,                      -- Fixed: Now permanent ID
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    day VARCHAR(20) NOT NULL,
    period INTEGER NOT NULL,
    type VARCHAR(20) NOT NULL,
    UNIQUE(user_id, day, period)
);

-- Session state table - Fixed SERIAL ID, removed session_id
CREATE TABLE IF NOT EXISTS session_state (
    id SERIAL PRIMARY KEY,                      -- Fixed: Now permanent ID
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    day VARCHAR(20) NOT NULL,
    period INTEGER NOT NULL,
    remaining_time INTEGER NOT NULL,
    current_task_index INTEGER NOT NULL,        -- References tasks.id
    task_start_time INTEGER NOT NULL,
    completed_task_ids INTEGER[] DEFAULT '{}',
    saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);

-- Feedback table - Fixed SERIAL ID
CREATE TABLE IF NOT EXISTS feedback (
    id SERIAL PRIMARY KEY,                      -- Fixed: Now permanent ID
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    feedback_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Courses table - For Marks tab and grade tracking
CREATE TABLE IF NOT EXISTS courses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    course_id BIGINT NOT NULL,                  -- Canvas course ID
    name VARCHAR(255) NOT NULL,                 -- Course name
    course_code VARCHAR(50),                    -- Course code (e.g., "ENG-11")
    current_score DECIMAL(5,2),                 -- Current percentage in course
    current_grade VARCHAR(10),                  -- Current letter grade
    final_score DECIMAL(5,2),                   -- Final percentage (if available)
    final_grade VARCHAR(10),                    -- Final letter grade
    enrollment_id BIGINT,                       -- Canvas enrollment ID
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, course_id)                  -- Prevent duplicate courses per user
);

-- Assignment groups table - For grade weight calculations
CREATE TABLE IF NOT EXISTS assignment_groups (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    course_id BIGINT NOT NULL,                  -- Which course this belongs to
    group_id BIGINT NOT NULL,                   -- Canvas assignment group ID
    name VARCHAR(255) NOT NULL,                 -- Category name (e.g., "Homework")
    weight DECIMAL(5,2),                        -- Percentage weight in final grade
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, course_id, group_id)        -- Prevent duplicates
);

-- NEW Tasks Completed table - Replaces completion_history
-- Consolidates segments automatically when all parts are complete
CREATE TABLE IF NOT EXISTS tasks_completed (
    id SERIAL PRIMARY KEY,                      -- Permanent ID (kept from original task when moved)
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,                -- Same as tasks.title
    class VARCHAR(200) NOT NULL,                -- Same as tasks.class
    description TEXT,                           -- Same as tasks.description
    url TEXT NOT NULL,                          -- Same as tasks.url (used for consolidation matching)
    deadline TIMESTAMP NOT NULL,                -- Same as tasks.deadline
    estimated_time INTEGER NOT NULL,            -- Merged: shows user_estimated_time OR estimated_time
    actual_time INTEGER NOT NULL,               -- Renamed from accumulated_time
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Users
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Tasks
CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_title ON tasks(title);
CREATE INDEX IF NOT EXISTS idx_tasks_class ON tasks(class);
CREATE INDEX IF NOT EXISTS idx_tasks_url ON tasks(url);
CREATE INDEX IF NOT EXISTS idx_tasks_deadline_date ON tasks(deadline_date);
CREATE INDEX IF NOT EXISTS idx_tasks_completed ON tasks(completed);
CREATE INDEX IF NOT EXISTS idx_tasks_priority_order ON tasks(priority_order);
CREATE INDEX IF NOT EXISTS idx_tasks_is_new ON tasks(is_new);
CREATE INDEX IF NOT EXISTS idx_tasks_segment ON tasks(segment);
CREATE INDEX IF NOT EXISTS idx_tasks_deleted ON tasks(deleted);
CREATE INDEX IF NOT EXISTS idx_tasks_assignment_id ON tasks(assignment_id);
CREATE INDEX IF NOT EXISTS idx_tasks_course_id ON tasks(course_id);
CREATE INDEX IF NOT EXISTS idx_tasks_assignment_group_id ON tasks(assignment_group_id);

-- Tasks Completed
CREATE INDEX IF NOT EXISTS idx_tasks_completed_user_id ON tasks_completed(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_url ON tasks_completed(url);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_class ON tasks_completed(class);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_title ON tasks_completed(title);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_completed_at ON tasks_completed(completed_at);

-- Schedules
CREATE INDEX IF NOT EXISTS idx_schedules_user_id ON schedules(user_id);

-- Session State
CREATE INDEX IF NOT EXISTS idx_session_state_user_id ON session_state(user_id);

-- Feedback
CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback(created_at);

-- Courses
CREATE INDEX IF NOT EXISTS idx_courses_user_id ON courses(user_id);
CREATE INDEX IF NOT EXISTS idx_courses_course_id ON courses(course_id);

-- Assignment Groups
CREATE INDEX IF NOT EXISTS idx_assignment_groups_user_id ON assignment_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_assignment_groups_course_id ON assignment_groups(course_id);
CREATE INDEX IF NOT EXISTS idx_assignment_groups_group_id ON assignment_groups(group_id);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to auto-update updated_at on users
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- MIGRATION SCRIPT - Run this on existing databases
-- ============================================================================

-- CRITICAL: This migration assumes you have MANUALLY dropped the old tasks table
-- If old tables exist, this will create the new structure alongside them

-- Nothing to migrate if starting fresh - the CREATE TABLE IF NOT EXISTS statements
-- above will create everything needed

-- If migrating from old system:
-- 1. Manually: DROP TABLE tasks CASCADE;
-- 2. Manually: DROP TABLE partial_completions CASCADE;
-- 3. Manually: DROP TABLE completion_history CASCADE;
-- 4. Run this entire schema file
-- 5. Re-import Canvas calendar data using the new endpoints

-- ============================================================================
-- TABLE COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE users IS 'Student user accounts with Canvas integration';

COMMENT ON TABLE tasks IS 'Active tasks imported from Canvas. Uses title/segment system for split tasks.';
COMMENT ON COLUMN tasks.title IS 'Base task name extracted from Canvas SUMMARY (before brackets). Never changes, identifies the original task.';
COMMENT ON COLUMN tasks.segment IS 'NULL for base tasks. For splits: "Part 1", "Hypothesis - First Phase", etc. Identifies current split state.';
COMMENT ON COLUMN tasks.class IS 'Extracted from brackets in Canvas SUMMARY. Example: [TAiLOR English]';
COMMENT ON COLUMN tasks.url IS 'Direct assignment URL converted from Canvas calendar URL format';
COMMENT ON COLUMN tasks.accumulated_time IS 'Replaces partial_completions table. Tracks time spent on incomplete tasks.';
COMMENT ON COLUMN tasks.deleted IS 'Marks tasks as deleted/ignored by user. Prevents re-import during sync while preserving history.';

COMMENT ON TABLE schedules IS 'User weekly schedule with fixed ID system';

COMMENT ON TABLE session_state IS 'Saved study session state for resume capability. Fixed ID, no session_id.';
COMMENT ON COLUMN session_state.current_task_index IS 'References the specific task.id being worked on';

COMMENT ON TABLE feedback IS 'User feedback, bug reports, and feature requests with fixed ID';

COMMENT ON TABLE tasks_completed IS 'Completed tasks with automatic segment consolidation. Replaces completion_history.';
COMMENT ON COLUMN tasks_completed.url IS 'Used to match and consolidate segments from the same original task';
COMMENT ON COLUMN tasks_completed.estimated_time IS 'Merged field: shows user_estimated_time if it was set, otherwise estimated_time';
COMMENT ON COLUMN tasks_completed.actual_time IS 'Total time spent. For consolidated tasks, sum of all segment times.';

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify tasks table structure
SELECT 
    'Tasks by type:' as check_type,
    CASE 
        WHEN segment IS NULL THEN 'Base Task'
        WHEN segment IS NOT NULL THEN 'Split Segment'
    END as task_type,
    COUNT(*) as count
FROM tasks
GROUP BY 
    CASE 
        WHEN segment IS NULL THEN 'Base Task'
        WHEN segment IS NOT NULL THEN 'Split Segment'
    END;

-- Show task examples
SELECT 
    id,
    user_id,
    LEFT(title, 40) as title,
    LEFT(segment, 30) as segment,
    LEFT(class, 20) as class,
    estimated_time,
    accumulated_time,
    completed
FROM tasks
ORDER BY user_id, title, segment
LIMIT 20;

-- Verify tasks_completed consolidation
SELECT 
    user_id,
    LEFT(title, 40) as title,
    LEFT(url, 60) as url,
    estimated_time,
    actual_time,
    completed_at
FROM tasks_completed
ORDER BY user_id, completed_at DESC
LIMIT 20;

-- Check for any orphaned session states
SELECT 
    ss.id,
    ss.user_id,
    ss.current_task_index,
    CASE 
        WHEN t.id IS NULL THEN 'ORPHANED - Task does not exist'
        ELSE 'OK'
    END as status
FROM session_state ss
LEFT JOIN tasks t ON ss.current_task_index = t.id AND ss.user_id = t.user_id;



-- Run this SQL to add the notes table
CREATE TABLE IF NOT EXISTS notes (
    task_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (task_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_notes_task_id ON notes(task_id);
CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);


-- ============================================================================
-- PlanAssist Hub Features - Database Migration
-- Adds: Completion Feed, Leaderboard, User Feed Preferences
-- ============================================================================

-- Add show_in_feed column to users table (defaults to true = opted in)
ALTER TABLE users ADD COLUMN IF NOT EXISTS show_in_feed BOOLEAN DEFAULT true;

-- Completion Feed Table
-- Stores recent task completions for the live feed
CREATE TABLE IF NOT EXISTS completion_feed (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_name VARCHAR(255) NOT NULL,
    user_grade VARCHAR(10),
    task_title VARCHAR(500) NOT NULL,
    task_class VARCHAR(200) NOT NULL,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for completion feed
CREATE INDEX IF NOT EXISTS idx_completion_feed_completed_at ON completion_feed(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_completion_feed_user_id ON completion_feed(user_id);

-- Weekly Leaderboard Table
-- Stores weekly task completion counts by grade
CREATE TABLE IF NOT EXISTS weekly_leaderboard (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_name VARCHAR(255) NOT NULL,
    grade VARCHAR(10) NOT NULL,
    tasks_completed INTEGER DEFAULT 0,
    week_start DATE NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, week_start)
);

-- Indexes for weekly leaderboard
CREATE INDEX IF NOT EXISTS idx_weekly_leaderboard_week_start ON weekly_leaderboard(week_start DESC);
CREATE INDEX IF NOT EXISTS idx_weekly_leaderboard_grade ON weekly_leaderboard(grade);
CREATE INDEX IF NOT EXISTS idx_weekly_leaderboard_tasks_completed ON weekly_leaderboard(tasks_completed DESC);

-- Comments for documentation
COMMENT ON TABLE completion_feed IS 'Live feed of recent task completions across all users (respecting privacy settings)';
COMMENT ON TABLE weekly_leaderboard IS 'Weekly task completion counts by grade, resets each Monday';
COMMENT ON COLUMN users.show_in_feed IS 'User preference: show completions in public feed (default true)';

-- Verification queries
SELECT 'Completion Feed Table Created' as status;
SELECT 'Weekly Leaderboard Table Created' as status;
SELECT 'Users table updated with show_in_feed column' as status;





-- Migration: Split deadline into deadline_date and deadline_time
-- This allows proper handling of date-only vs datetime assignments from Canvas

-- Step 1: Add new columns
ALTER TABLE tasks 
ADD COLUMN IF NOT EXISTS deadline_date DATE,
ADD COLUMN IF NOT EXISTS deadline_time TIME;

-- Step 2: Migrate existing data (if any exists)
-- Parse existing deadline column into date and time components (only if deadline column still exists)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'tasks' AND column_name = 'deadline'
  ) THEN
    UPDATE tasks
    SET 
      deadline_date = CASE 
        WHEN deadline IS NOT NULL THEN DATE(deadline)
        ELSE NULL
      END,
      deadline_time = CASE 
        WHEN deadline IS NOT NULL AND deadline::text LIKE '%:%' THEN 
          CASE 
            WHEN deadline::TIME != '23:59:00'::time THEN deadline::TIME
            ELSE NULL
          END
        ELSE NULL
      END
    WHERE deadline IS NOT NULL;
  END IF;
END $$;

-- Step 3: Drop old deadline column (safe even if already dropped)
ALTER TABLE tasks DROP COLUMN IF EXISTS deadline;

-- Step 4: Add constraints
ALTER TABLE tasks ALTER COLUMN deadline_date SET NOT NULL;
-- deadline_time can be NULL (for date-only assignments)

-- Step 5: Update indexes
DROP INDEX IF EXISTS idx_tasks_deadline;
CREATE INDEX IF NOT EXISTS idx_tasks_deadline_date ON tasks(deadline_date);

-- Step 6: Do the same for tasks_completed table
ALTER TABLE tasks_completed 
ADD COLUMN IF NOT EXISTS deadline_date DATE,
ADD COLUMN IF NOT EXISTS deadline_time TIME;

-- Only migrate if the old deadline column still exists
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'tasks_completed' AND column_name = 'deadline'
  ) THEN
    UPDATE tasks_completed
    SET 
      deadline_date = CASE 
        WHEN deadline IS NOT NULL THEN DATE(deadline)
        ELSE NULL
      END,
      deadline_time = CASE 
        WHEN deadline IS NOT NULL AND deadline::text LIKE '%:%' THEN 
          CASE 
            WHEN deadline::TIME != '23:59:00'::time THEN deadline::TIME
            ELSE NULL
          END
        ELSE NULL
      END
    WHERE deadline IS NOT NULL;

    ALTER TABLE tasks_completed DROP COLUMN IF EXISTS deadline;
  END IF;
END $$;

ALTER TABLE tasks_completed ALTER COLUMN deadline_date SET NOT NULL;

DROP INDEX IF EXISTS idx_tasks_completed_deadline;
CREATE INDEX IF NOT EXISTS idx_tasks_completed_deadline_date ON tasks_completed(deadline_date);

-- Migration: Add calendar preference columns to users table
-- Safe: IF NOT EXISTS is idempotent, existing rows get the defaults

ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_today_centered BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_show_homeroom  BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_show_completed BOOLEAN DEFAULT true;

ALTER TABLE session_state 
  ADD COLUMN IF NOT EXISTS partial_task_times JSONB DEFAULT NULL;

-- Add current grading period score columns to courses table
ALTER TABLE courses
  ADD COLUMN IF NOT EXISTS current_period_score NUMERIC,
  ADD COLUMN IF NOT EXISTS current_period_grade TEXT,
  ADD COLUMN IF NOT EXISTS grading_period_id INTEGER,
  ADD COLUMN IF NOT EXISTS grading_period_title TEXT;


-- Add session_active flag to tasks table
-- Tracks whether a task currently has an in-progress timer session
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS session_active BOOLEAN DEFAULT false;

-- Drop old sessions infrastructure (no longer needed)
DROP TABLE IF EXISTS user_sessions;

-- Agendas table
CREATE TABLE IF NOT EXISTS agendas (
  id            SERIAL PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  task_ids      INTEGER[] NOT NULL,          -- ordered list of 1-3 task IDs
  finished      BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS agendas_user_id_idx ON agendas(user_id);

COMMENT ON TABLE agendas IS 'User-created agenda blocks grouping 1-3 tasks for a focused work session.';
COMMENT ON COLUMN agendas.task_ids IS 'Ordered array of task IDs (max 3). Tasks can appear in multiple agendas.';
COMMENT ON COLUMN agendas.finished IS 'True once all tasks in the agenda have been marked complete.';

-- ============================================================
-- Migration: Itinerary feature (uses existing schedules table)
-- ============================================================

-- 1. Add unique constraint to schedules so ON CONFLICT works for upserts
ALTER TABLE schedules
  ADD CONSTRAINT schedules_user_day_period_unique UNIQUE (user_id, day, period);

-- 2. Add course columns to existing schedules table
ALTER TABLE schedules
  ADD COLUMN IF NOT EXISTS course_id   INTEGER REFERENCES courses(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS course_name TEXT;

-- 3. Add schedule_enhanced flag to users
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS schedule_enhanced BOOLEAN NOT NULL DEFAULT false;

-- 4. Add zoom_number to courses
ALTER TABLE courses
  ADD COLUMN IF NOT EXISTS zoom_number TEXT;

-- 5. Itinerary slots table: maps each Study period slot to an agenda for a given day
CREATE TABLE IF NOT EXISTS itinerary_slots (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  day        TEXT NOT NULL,
  period     INTEGER NOT NULL,
  agenda_id  INTEGER REFERENCES agendas(id) ON DELETE SET NULL,
  UNIQUE (user_id, day, period)
);

CREATE INDEX IF NOT EXISTS itinerary_slots_user_idx ON itinerary_slots(user_id);

COMMENT ON COLUMN schedules.course_id   IS 'Course assigned to this Lesson period (enhanced schedule).';
COMMENT ON COLUMN schedules.course_name IS 'Denormalised course name for display.';
COMMENT ON TABLE  itinerary_slots       IS 'Maps each Study period slot in the Itinerary to an agenda.';

-- ============================================================
-- Migration: Tutorials feature
-- ============================================================

CREATE TABLE IF NOT EXISTS tutorials (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  day         TEXT NOT NULL,       -- 'Monday', 'Tuesday', etc.
  period      INTEGER NOT NULL,
  zoom_number TEXT,
  topic       TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, day, period)    -- one tutorial per day/period slot
);

CREATE INDEX IF NOT EXISTS tutorials_user_idx ON tutorials(user_id);

COMMENT ON TABLE tutorials IS 'Stores booked tutorial sessions per day/period slot.';

-- ============================================================
-- Migration: Misc fixes
-- ============================================================

-- 1. Add manually_created flag to tasks
ALTER TABLE tasks
  ADD COLUMN IF NOT EXISTS manually_created BOOLEAN NOT NULL DEFAULT false;

-- 2. Mark existing split-task segments as manually_created=false (default),
--    they are handled by Sync guard logic not this flag
-- (no data migration needed for segments)

-- 3. Trigger a one-time priority reorder for all users
--    (fixes gaps created by manual DB edits - item #4)
WITH ordered AS (
  SELECT id,
    ROW_NUMBER() OVER (
      PARTITION BY user_id
      ORDER BY priority_order ASC NULLS LAST, deadline_date ASC, deadline_time ASC NULLS LAST
    ) AS new_order
  FROM tasks
  WHERE deleted = false AND completed = false AND priority_order IS NOT NULL
)
UPDATE tasks SET priority_order = ordered.new_order
FROM ordered WHERE tasks.id = ordered.id;

-- ============================================================
-- Migration: Admin Console
-- ============================================================

-- 1. Add admin/ban columns to users
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS ban_reason TEXT;

-- 2. Admin audit log
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id SERIAL PRIMARY KEY,
  admin_id INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  admin_name TEXT NOT NULL,
  action TEXT NOT NULL,          -- e.g. 'BAN_USER', 'EDIT_USER', 'DISMISS_ANNOUNCEMENT'
  target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  target_user_name TEXT,
  details JSONB,                 -- flexible payload for action-specific data
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Announcements (persistent banners)
CREATE TABLE IF NOT EXISTS announcements (
  id SERIAL PRIMARY KEY,
  author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  author_name TEXT NOT NULL,
  message TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'info',   -- 'info' (dismissible, blue) | 'urgent' (non-dismissible, red/orange)
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deactivated_at TIMESTAMPTZ
);

-- 4. Per-user announcement dismissals (only used for dismissible announcements)
CREATE TABLE IF NOT EXISTS announcement_dismissals (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  announcement_id INTEGER NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
  dismissed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, announcement_id)
);

-- Add split_origin column to tasks
ALTER TABLE tasks
  ADD COLUMN IF NOT EXISTS split_origin BOOLEAN NOT NULL DEFAULT false;

-- Backfill: mark existing split-origin tasks
-- A split-origin task is deleted=true, has a url, and at least one segment sibling
-- exists with the same url and user_id
UPDATE tasks t
SET split_origin = true
WHERE t.deleted = true
  AND t.completed = false
  AND t.url IS NOT NULL
  AND t.segment IS NULL
  AND EXISTS (
    SELECT 1 FROM tasks seg
    WHERE seg.user_id = t.user_id
      AND seg.url = t.url
      AND seg.segment IS NOT NULL
  );

-- ============================================================
-- PlanAssist Migration: Account & Analytics Revamp
-- Run in Supabase SQL Editor
-- ============================================================

-- 1. Add 'ignored' column to tasks table
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS ignored BOOLEAN DEFAULT FALSE;

-- 2. Add 'enabled' column to courses table (controls visibility everywhere)
ALTER TABLE courses ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT TRUE;

-- 3. Add help_content table (global, admin-editable)
CREATE TABLE IF NOT EXISTS help_content (
  id INTEGER PRIMARY KEY DEFAULT 1,
  content TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_by INTEGER REFERENCES users(id)
);

-- Seed a default row so there's always one to UPDATE
INSERT INTO help_content (id, content) VALUES (1, '')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- Done. Deploy server.js and App.jsx after running this.
-- ============================================================

-- Add grade_id column to tasks for tracking grade detection order
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS grade_id INTEGER DEFAULT NULL;

-- Index for efficient lookup of max grade_id per user
CREATE INDEX IF NOT EXISTS idx_tasks_user_grade_id ON tasks (user_id, grade_id) WHERE grade_id IS NOT NULL;

-- ============================================================
-- Agendas v2 migration
-- Replaces task_ids[] with a rows JSONB column and adds
-- per-row progress tracking columns.
-- ============================================================

-- Add new columns
ALTER TABLE agendas
  ADD COLUMN IF NOT EXISTS rows        JSONB    NOT NULL DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS current_row INTEGER  NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS current_row_elapsed  INTEGER  NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS current_row_countdown INTEGER  DEFAULT NULL;

-- Migrate existing agendas: convert task_ids[] → rows JSONB
-- Each task becomes a row with action='Work on Task' and
-- timeMins = the task's estimated_time (or 25 if null).
UPDATE agendas a
SET rows = (
  SELECT jsonb_agg(
    jsonb_build_object(
      'rowIndex',  ordinality - 1,
      'taskId',    tid,
      'action',    'Work on Task',
      'timeMins',  COALESCE(
                     (SELECT COALESCE(user_estimated_time, estimated_time)
                      FROM tasks
                      WHERE id = tid AND user_id = a.user_id
                      LIMIT 1),
                     25
                   )
    )
    ORDER BY ordinality
  )
  FROM unnest(a.task_ids) WITH ORDINALITY AS t(tid, ordinality)
)
WHERE array_length(task_ids, 1) > 0;

-- Drop the old column (safe after migration)
ALTER TABLE agendas DROP COLUMN IF EXISTS task_ids;

-- Update the comment
COMMENT ON TABLE agendas IS 'User-created agenda blocks with ordered rows of task+action+time.';
COMMENT ON COLUMN agendas.rows IS 'JSONB array of {rowIndex, taskId, action, timeMins}. Max 10 rows.';
COMMENT ON COLUMN agendas.current_row IS '0-based index of the row currently being worked on.';
COMMENT ON COLUMN agendas.current_row_elapsed IS 'Seconds spent on in-session timer for current row (saved on exit).';
COMMENT ON COLUMN agendas.current_row_countdown IS 'Seconds remaining on countdown timer when user saved and exited. NULL = full timeMins.';

-- Widen grading_type column to accommodate all Canvas grading type strings
-- Canvas values include: 'points', 'percent', 'letter_grade', 'gpa_scale', 'not_graded', 'pass_fail'
-- Previous VARCHAR(10) was too narrow for 'letter_grade' (12 chars)
ALTER TABLE tasks ALTER COLUMN grading_type TYPE VARCHAR(200);

-- Fix VARCHAR columns that are too narrow for Canvas API data
-- current_grade: Canvas can return values longer than 10 chars
ALTER TABLE tasks ALTER COLUMN current_grade TYPE VARCHAR(50);

-- courses table has the same issue  
ALTER TABLE courses ALTER COLUMN current_grade TYPE VARCHAR(50);
ALTER TABLE courses ALTER COLUMN final_grade TYPE VARCHAR(50);

-- grading_type: was VARCHAR(20) in schema but VARCHAR(10) may have been applied
-- 'letter_grade' is 12 chars, set generously
ALTER TABLE tasks ALTER COLUMN grading_type TYPE VARCHAR(50);

-- completion_feed and leaderboard grade columns (if they exist)
ALTER TABLE weekly_leaderboard ALTER COLUMN grade TYPE VARCHAR(50);
ALTER TABLE completion_feed ALTER COLUMN user_grade TYPE VARCHAR(50);

SELECT 
  'Tasks table migration complete' as status,
  COUNT(*) as total_tasks,
  COUNT(deadline_time) as tasks_with_time,
  COUNT(*) - COUNT(deadline_time) as tasks_date_only
FROM tasks;

SELECT 
  'Tasks completed table migration complete' as status,
  COUNT(*) as total_tasks,
  COUNT(deadline_time) as tasks_with_time,
  COUNT(*) - COUNT(deadline_time) as tasks_date_only
FROM tasks_completed;

-- UPDATE!


-- Feature 1: Itinerary date column
ALTER TABLE itinerary_slots ADD COLUMN IF NOT EXISTS date DATE;
UPDATE itinerary_slots SET date = NULL;
ALTER TABLE itinerary_slots DROP CONSTRAINT IF EXISTS itinerary_slots_user_id_day_period_key;
ALTER TABLE itinerary_slots ADD CONSTRAINT itinerary_slots_user_date_period_unique UNIQUE (user_id, date, period);

-- Feature 1: Tutorials date column (replace day)
ALTER TABLE tutorials ADD COLUMN IF NOT EXISTS date DATE;
UPDATE tutorials SET date = NULL;
ALTER TABLE tutorials DROP CONSTRAINT IF EXISTS tutorials_user_id_day_period_key;
ALTER TABLE tutorials ADD CONSTRAINT tutorials_user_date_period_unique UNIQUE (user_id, date, period);

-- Feature 2: Calendar week toggle columns
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS calendar_show_prev_week BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS calendar_show_current_week BOOLEAN DEFAULT true,
  ADD COLUMN IF NOT EXISTS calendar_show_next_week1 BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS calendar_show_next_week2 BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS calendar_show_weekends BOOLEAN DEFAULT true;



-- UPDATE!


-- 1. Remove the now-unused calendar_today_centered column
ALTER TABLE users DROP COLUMN IF EXISTS calendar_today_centered;

-- 2. Drop the day column from itinerary_slots
ALTER TABLE itinerary_slots DROP COLUMN IF EXISTS day;

-- 3. Drop the day column from tutorials
ALTER TABLE tutorials DROP COLUMN IF EXISTS day;

-- 4. Drop the old day-based constraint on itinerary_slots (if it still exists)
ALTER TABLE itinerary_slots DROP CONSTRAINT IF EXISTS itinerary_slots_user_id_day_period_key;

-- 5. Drop the old day-based constraint on tutorials (if it still exists)
ALTER TABLE tutorials DROP CONSTRAINT IF EXISTS tutorials_user_id_day_period_key;

-- 6. Ensure tutorials has the date-based unique constraint
ALTER TABLE tutorials ADD CONSTRAINT tutorials_user_date_period_unique UNIQUE (user_id, date, period);



-- Feature 1: Itinerary date column
ALTER TABLE itinerary_slots ADD COLUMN IF NOT EXISTS date DATE;
UPDATE itinerary_slots SET date = NULL;
ALTER TABLE itinerary_slots DROP CONSTRAINT IF EXISTS itinerary_slots_user_id_day_period_key;
ALTER TABLE itinerary_slots ADD CONSTRAINT itinerary_slots_user_date_period_unique UNIQUE (user_id, date, period);

-- Feature 1: Tutorials date column (replace day)
ALTER TABLE tutorials ADD COLUMN IF NOT EXISTS date DATE;
UPDATE tutorials SET date = NULL;
ALTER TABLE tutorials DROP CONSTRAINT IF EXISTS tutorials_user_id_day_period_key;
ALTER TABLE tutorials ADD CONSTRAINT tutorials_user_date_period_unique UNIQUE (user_id, date, period);

-- Feature 2: Calendar week toggle columns
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS calendar_show_prev_week BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS calendar_show_current_week BOOLEAN DEFAULT true,
  ADD COLUMN IF NOT EXISTS calendar_show_next_week1 BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS calendar_show_next_week2 BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS calendar_show_weekends BOOLEAN DEFAULT true;



-- 1. Remove the now-unused calendar_today_centered column
ALTER TABLE users DROP COLUMN IF EXISTS calendar_today_centered;

-- 2. Drop the day column from itinerary_slots
ALTER TABLE itinerary_slots DROP COLUMN IF EXISTS day;

-- 3. Drop the day column from tutorials
ALTER TABLE tutorials DROP COLUMN IF EXISTS day;

-- 4. Drop the old day-based constraint on itinerary_slots (if it still exists)
ALTER TABLE itinerary_slots DROP CONSTRAINT IF EXISTS itinerary_slots_user_id_day_period_key;

-- 5. Drop the old day-based constraint on tutorials (if it still exists)
ALTER TABLE tutorials DROP CONSTRAINT IF EXISTS tutorials_user_id_day_period_key;

-- 6. Ensure tutorials has the date-based unique constraint
ALTER TABLE tutorials ADD CONSTRAINT tutorials_user_date_period_unique UNIQUE (user_id, date, period);



-- 1. Drop priority_order (already done if you ran the previous migration)
ALTER TABLE tasks DROP COLUMN IF EXISTS priority_order;

-- 2. Drop is_new — tasks are now always immediately visible, sorted by deadline
ALTER TABLE tasks DROP COLUMN IF EXISTS is_new;

-- 3. Drop ignored — tasks are now marked deleted=true directly
--    (Keep this if you want to preserve the ignored→resolved distinction on the Resolved Tasks page)
-- ALTER TABLE tasks DROP COLUMN IF EXISTS ignored;

-- 4. Create session_priorities table
CREATE TABLE IF NOT EXISTS session_priorities (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    task_ids JSONB NOT NULL DEFAULT '[]',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, date)
);
CREATE INDEX IF NOT EXISTS idx_session_priorities_user_date ON session_priorities(user_id, date);



ALTER TABLE users DROP COLUMN IF EXISTS email_notifications;



-- ============================================================================
-- Migration: Add last_sync column to users table
-- Tracks when Main Sync or Background Sync last completed for a user.
-- Used by: Diagnostics "Stale Syncs" report, login-time sync decision,
--          Admin Console Users tab, Background Sync updated_since parameter.
-- ============================================================================
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_sync TIMESTAMP;

-- Backfill from MAX(tasks.created_at) for existing users so existing data
-- doesn't make everyone appear as "never synced"
UPDATE users u
SET last_sync = (
  SELECT MAX(t.created_at)
  FROM tasks t
  WHERE t.user_id = u.id
)
WHERE u.last_sync IS NULL;

-- Index for Diagnostics query (ORDER BY last_sync ASC NULLS FIRST)
CREATE INDEX IF NOT EXISTS idx_users_last_sync ON users(last_sync ASC NULLS FIRST);





-- ============================================================================
-- PlanAssist Feature Migration
-- Covers: Streak Shields, Feed Labels, Reactions, Announcements targeting,
--         Gallery badges, last_sync (if not already added)
-- ============================================================================

-- ── 1. Users table additions ────────────────────────────────────────────────
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS streak_shields_available INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS streak_shield_mode VARCHAR(10) DEFAULT 'manual'
    CHECK (streak_shield_mode IN ('manual', 'automatic')),
  ADD COLUMN IF NOT EXISTS feed_label_days INTEGER DEFAULT 0,      -- days with ≥1 task completed (never resets)
  ADD COLUMN IF NOT EXISTS feed_label_selected VARCHAR(30) DEFAULT 'completed',
  ADD COLUMN IF NOT EXISTS last_sync TIMESTAMP;                     -- idempotent if already added

-- Index for admin health score sort (last_sync)
CREATE INDEX IF NOT EXISTS idx_users_last_sync ON users(last_sync ASC NULLS FIRST);

-- ── 2. Streak shields log ───────────────────────────────────────────────────
-- Each row records one day a shield was consumed (used to fill streak gaps).
CREATE TABLE IF NOT EXISTS streak_shield_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    shield_date DATE NOT NULL,          -- The weekday the shield covered
    consumed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, shield_date)        -- One shield per day per user
);
CREATE INDEX IF NOT EXISTS idx_streak_shield_log_user ON streak_shield_log(user_id, shield_date DESC);

-- ── 3. Feed reactions ───────────────────────────────────────────────────────
-- One reaction per user per feed entry, replace on change.
CREATE TABLE IF NOT EXISTS feed_reactions (
    id SERIAL PRIMARY KEY,
    feed_entry_id INTEGER NOT NULL REFERENCES completion_feed(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji VARCHAR(10) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(feed_entry_id, user_id)      -- one reaction per user per entry
);
CREATE INDEX IF NOT EXISTS idx_feed_reactions_entry ON feed_reactions(feed_entry_id);
CREATE INDEX IF NOT EXISTS idx_feed_reactions_user ON feed_reactions(user_id);

-- ── 4. Feed label unlock tracking ──────────────────────────────────────────
-- Records which labels each user has unlocked (for UI display).
CREATE TABLE IF NOT EXISTS feed_label_unlocks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label VARCHAR(30) NOT NULL,
    unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, label)
);
CREATE INDEX IF NOT EXISTS idx_feed_label_unlocks_user ON feed_label_unlocks(user_id);

-- ── 5. Gallery badges ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_badges (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    badge_key VARCHAR(60) NOT NULL,     -- e.g. 'first_completion', 'streak_7', 'tasks_50'
    awarded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, badge_key)
);
CREATE INDEX IF NOT EXISTS idx_user_badges_user ON user_badges(user_id);

-- ── 6. Announcements: add targeting column ──────────────────────────────────
-- 'all' = everyone, 'existing' = users created before announcement, 'new' = after
ALTER TABLE announcements
  ADD COLUMN IF NOT EXISTS target_audience VARCHAR(20) DEFAULT 'all'
    CHECK (target_audience IN ('all', 'existing', 'new'));

-- ── 7. Backfill: feed_label_days from existing tasks_completed data ─────────
-- Count distinct days each user has completed ≥1 task.
UPDATE users u
SET feed_label_days = (
    SELECT COUNT(DISTINCT tc.completed_at::date)
    FROM tasks_completed tc
    WHERE tc.user_id = u.id
)
WHERE feed_label_days = 0;

-- ── 8. Backfill: feed_label_unlocks from current feed_label_days ────────────
-- Unlocks all labels the user has already earned.
DO $$
DECLARE
  label_thresholds INT[] := ARRAY[0,5,10,20,30,40,50,60,70,80,90,100,120,140,160,180,200,250,300,400,500];
  label_words TEXT[] := ARRAY['completed','finished','did','handled','closed','processed','resolved',
    'settled','finalized','accomplished','achieved','fulfilled','delivered','executed','cleared',
    'dispatched','secured','conquered','crushed','dominated','mastered'];
  rec RECORD;
  i INT;
BEGIN
  FOR rec IN SELECT id, feed_label_days FROM users LOOP
    FOR i IN 1..array_length(label_thresholds, 1) LOOP
      IF rec.feed_label_days >= label_thresholds[i] THEN
        INSERT INTO feed_label_unlocks (user_id, label)
        VALUES (rec.id, label_words[i])
        ON CONFLICT (user_id, label) DO NOTHING;
      END IF;
    END LOOP;
    -- Set selected label to highest unlocked
    DECLARE highest TEXT := 'completed';
    BEGIN
      FOR i IN REVERSE array_length(label_thresholds, 1)..1 LOOP
        IF rec.feed_label_days >= label_thresholds[i] THEN
          highest := label_words[i];
          EXIT;
        END IF;
      END LOOP;
      UPDATE users SET feed_label_selected = highest WHERE id = rec.id;
    END;
  END LOOP;
END $$;

-- ── 9. Backfill: gallery badges from existing data ──────────────────────────
-- Badge: first_completion
INSERT INTO user_badges (user_id, badge_key, awarded_at)
SELECT DISTINCT tc.user_id, 'first_completion', MIN(tc.completed_at)
FROM tasks_completed tc
GROUP BY tc.user_id
ON CONFLICT DO NOTHING;

-- Badge: tasks_10, tasks_25, tasks_50, tasks_100, tasks_250, tasks_500
DO $$
DECLARE
  thresholds INT[] := ARRAY[10,25,50,100,250,500];
  t INT;
  rec RECORD;
  cnt INT;
  aw TIMESTAMP;
BEGIN
  FOR rec IN SELECT user_id, COUNT(*) as total FROM tasks_completed GROUP BY user_id LOOP
    FOREACH t IN ARRAY thresholds LOOP
      IF rec.total >= t THEN
        SELECT completed_at INTO aw FROM (
          SELECT completed_at FROM tasks_completed WHERE user_id = rec.user_id
          ORDER BY completed_at ASC LIMIT t
        ) sub ORDER BY completed_at DESC LIMIT 1;
        INSERT INTO user_badges (user_id, badge_key, awarded_at)
        VALUES (rec.user_id, 'tasks_' || t, aw)
        ON CONFLICT DO NOTHING;
      END IF;
    END LOOP;
  END LOOP;
END $$;

-- Badge: streak_7, streak_14, streak_30 (best day streak from tasks_completed)
-- (streak calculation is done client-side; we award these badges via the backend on Hub load)

-- Badge: most_in_day (most tasks in a single day)
INSERT INTO user_badges (user_id, badge_key, awarded_at)
SELECT tc.user_id, 'most_in_day_' || MAX(daily.cnt), MIN(tc.completed_at)
FROM tasks_completed tc
JOIN (
  SELECT user_id, completed_at::date AS day, COUNT(*) AS cnt
  FROM tasks_completed
  GROUP BY user_id, completed_at::date
) daily ON daily.user_id = tc.user_id
GROUP BY tc.user_id
ON CONFLICT DO NOTHING;

-- ── 10. Completion_feed: add feed_label column ──────────────────────────────
ALTER TABLE completion_feed
  ADD COLUMN IF NOT EXISTS feed_label VARCHAR(30) DEFAULT 'completed';


-- Correction: Reset all users' feed_label_selected back to 'completed'
-- The previous backfill auto-selected the highest unlocked label, but the
-- spec says the default should always be 'completed' and users must manually choose.
-- Unlocked labels are preserved — only the active selection is reset.
UPDATE users SET feed_label_selected = 'completed';


-- ============================================================================
-- MIGRATION: Feed Label → Insignia system
-- Replaces word-based feed labels with tiered name Insignias
-- ============================================================================

-- ── 11. Rename feed_label_unlocks table → insignia_unlocks ──────────────────
-- We keep the same structure but rename for clarity.
-- Existing rows (old label strings) are cleared since tier names changed.
ALTER TABLE feed_label_unlocks RENAME TO insignia_unlocks;

-- Clear old label unlock records (old tier names are no longer valid)
DELETE FROM insignia_unlocks;

-- ── 12. Rename columns: users table ─────────────────────────────────────────
ALTER TABLE users
  RENAME COLUMN feed_label_days TO insignia_days;
ALTER TABLE users
  RENAME COLUMN feed_label_selected TO insignia_selected;

-- ── 13. Rename column: completion_feed table ─────────────────────────────────
ALTER TABLE completion_feed
  RENAME COLUMN feed_label TO insignia;

-- ── 14. Reset insignia_selected to new default tier name 'Default' ───────────
UPDATE users SET insignia_selected = 'Default';

-- ── 15. Backfill insignia_unlocks from current insignia_days ─────────────────
-- Re-run unlock logic for all users using new Insignia thresholds
DO $$
DECLARE
  tier_thresholds INT[]  := ARRAY[0, 2, 5, 10, 20, 30, 40, 50, 75, 100];
  tier_labels     TEXT[] := ARRAY['Default','Copper','Silver','Gold','Emerald','Amethyst','Ruby','Diamond','Obsidian','Aether'];
  rec RECORD;
  i INT;
BEGIN
  FOR rec IN SELECT id, insignia_days FROM users LOOP
    FOR i IN 1..array_length(tier_thresholds, 1) LOOP
      IF rec.insignia_days >= tier_thresholds[i] THEN
        INSERT INTO insignia_unlocks (user_id, label)
        VALUES (rec.id, tier_labels[i])
        ON CONFLICT DO NOTHING;
      END IF;
    END LOOP;
  END LOOP;
END $$;

-- ── 16. Set insignia_selected to highest unlocked Insignia per user ───────────
-- Gives each user their best earned Insignia automatically.
-- Users can override any time in the Insignia pane.
DO $$
DECLARE
  tier_thresholds INT[]  := ARRAY[0, 2, 5, 10, 20, 30, 40, 50, 75, 100];
  tier_labels     TEXT[] := ARRAY['Default','Copper','Silver','Gold','Emerald','Amethyst','Ruby','Diamond','Obsidian','Aether'];
  rec RECORD;
  highest TEXT := 'Default';
  i INT;
BEGIN
  FOR rec IN SELECT id, insignia_days FROM users LOOP
    highest := 'Default';
    FOR i IN array_length(tier_thresholds, 1) .. 1 BY -1 LOOP
      IF rec.insignia_days >= tier_thresholds[i] THEN
        highest := tier_labels[i];
        EXIT;
      END IF;
    END LOOP;
    UPDATE users SET insignia_selected = highest WHERE id = rec.id;
  END LOOP;
END $$;

-- ── 17. Update completion_feed.insignia default to new tier name ─────────────
ALTER TABLE completion_feed
  ALTER COLUMN insignia SET DEFAULT 'Default';
