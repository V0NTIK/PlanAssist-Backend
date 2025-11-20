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

-- Users table (unchanged)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    grade VARCHAR(10),
    canvas_url TEXT,
    present_periods VARCHAR(10) DEFAULT '2-6',
    is_new_user BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- NEW Tasks table - Completely redesigned with title/segment system
CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,                      -- Permanent unique ID for each task/segment
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,                -- Base task name (never changes, acts like old parent_id)
    segment VARCHAR(500),                       -- NULL for base tasks, "Part 1" or "Hypothesis - First Phase" for splits
    class VARCHAR(200) NOT NULL,                -- Extracted from brackets in SUMMARY [TAiLOR English]
    description TEXT,                           -- From DESCRIPTION field in ICS
    url TEXT NOT NULL,                          -- Converted from calendar URL to assignment URL
    deadline TIMESTAMP NOT NULL,                -- From DTSTART/DTEND in ICS
    estimated_time INTEGER NOT NULL,            -- AI-calculated estimate (minutes)
    user_estimated_time INTEGER,                -- User override (NULL if not set)
    accumulated_time INTEGER DEFAULT 0,         -- Replaces partial_completions table
    completed BOOLEAN DEFAULT FALSE,            -- When TRUE, moves to tasks_completed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    priority_order INTEGER,                     -- Manual priority override (NULL by default)
    is_new BOOLEAN DEFAULT FALSE,               -- Marks newly imported tasks
    deleted BOOLEAN DEFAULT FALSE               -- Marks tasks as deleted/checked off without removing from database
);

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
CREATE INDEX IF NOT EXISTS idx_tasks_deadline ON tasks(deadline);
CREATE INDEX IF NOT EXISTS idx_tasks_completed ON tasks(completed);
CREATE INDEX IF NOT EXISTS idx_tasks_priority_order ON tasks(priority_order);
CREATE INDEX IF NOT EXISTS idx_tasks_is_new ON tasks(is_new);
CREATE INDEX IF NOT EXISTS idx_tasks_segment ON tasks(segment);
CREATE INDEX IF NOT EXISTS idx_tasks_deleted ON tasks(deleted);

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
