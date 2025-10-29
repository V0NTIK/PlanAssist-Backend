-- PlanAssist - FIXED Database Schema with Proper Two-ID System
-- This schema ensures ALL tasks have parent_task_id set correctly

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
    priority_locked BOOLEAN DEFAULT FALSE,
    is_new_user BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tasks table - FIXED: parent_task_id should never be NULL after creation
CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    due_date TIMESTAMP NOT NULL,
    task_type VARCHAR(50),
    estimated_time INTEGER NOT NULL,
    user_estimate INTEGER,
    priority_order INTEGER,
    is_new BOOLEAN DEFAULT FALSE,
    completed BOOLEAN DEFAULT FALSE,
    -- TWO-ID SYSTEM:
    parent_task_id INTEGER,           -- Self-referential for base tasks, references original for splits
    split_task_id INTEGER,            -- NULL for base tasks, 1,2,3... for segments
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Schedules table (unchanged)
CREATE TABLE IF NOT EXISTS schedules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    day VARCHAR(20) NOT NULL,
    period INTEGER NOT NULL,
    type VARCHAR(20) NOT NULL,
    UNIQUE(user_id, day, period)
);

-- Partial completions table - mirrors task IDs exactly
CREATE TABLE IF NOT EXISTS partial_completions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL,              -- Specific segment being worked on
    parent_task_id INTEGER NOT NULL,       -- REQUIRED: matches task's parent_task_id
    split_task_id INTEGER,                 -- Optional: matches task's split_task_id
    task_title VARCHAR(500) NOT NULL,
    accumulated_time INTEGER NOT NULL DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, task_id)
);

-- Completion history (for AI learning and consolidation)
CREATE TABLE IF NOT EXISTS completion_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    task_id INTEGER,
    parent_task_id INTEGER NOT NULL,       -- REQUIRED: for grouping segments
    task_title VARCHAR(500),
    task_type VARCHAR(50),
    estimated_time INTEGER,
    actual_time INTEGER,
    is_segment BOOLEAN DEFAULT FALSE,      -- TRUE for individual segments, FALSE for consolidated
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Session state table (for resume capability)
CREATE TABLE IF NOT EXISTS session_state (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(100) NOT NULL,
    day VARCHAR(20) NOT NULL,
    period INTEGER NOT NULL,
    remaining_time INTEGER NOT NULL,
    current_task_index INTEGER NOT NULL,
    task_start_time INTEGER NOT NULL,
    completed_task_ids INTEGER[] DEFAULT '{}',
    saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);

-- Feedback table (unchanged)
CREATE TABLE IF NOT EXISTS feedback (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    feedback_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_due_date ON tasks(due_date);
CREATE INDEX IF NOT EXISTS idx_tasks_completed ON tasks(completed);
CREATE INDEX IF NOT EXISTS idx_tasks_priority_order ON tasks(priority_order);
CREATE INDEX IF NOT EXISTS idx_tasks_is_new ON tasks(is_new);
CREATE INDEX IF NOT EXISTS idx_tasks_parent_task_id ON tasks(parent_task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_split_task_id ON tasks(split_task_id);
CREATE INDEX IF NOT EXISTS idx_schedules_user_id ON schedules(user_id);
CREATE INDEX IF NOT EXISTS idx_partial_completions_user_id ON partial_completions(user_id);
CREATE INDEX IF NOT EXISTS idx_partial_completions_task_id ON partial_completions(task_id);
CREATE INDEX IF NOT EXISTS idx_partial_completions_parent_task_id ON partial_completions(parent_task_id);
CREATE INDEX IF NOT EXISTS idx_completion_history_user_id ON completion_history(user_id);
CREATE INDEX IF NOT EXISTS idx_completion_history_parent_task_id ON completion_history(parent_task_id);
CREATE INDEX IF NOT EXISTS idx_completion_history_type ON completion_history(task_type);
CREATE INDEX IF NOT EXISTS idx_completion_history_is_segment ON completion_history(is_segment);
CREATE INDEX IF NOT EXISTS idx_session_state_user_id ON session_state(user_id);
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

-- Trigger for partial_completions last_updated
DROP TRIGGER IF EXISTS update_partial_completions_updated_at ON partial_completions;
CREATE TRIGGER update_partial_completions_updated_at BEFORE UPDATE ON partial_completions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- MIGRATION SCRIPT - Run this on existing databases
-- ============================================================================

-- Step 1: Ensure all columns exist (safe to run multiple times)
DO $$ 
BEGIN
    -- Add parent_task_id to tasks if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'tasks' AND column_name = 'parent_task_id') THEN
        ALTER TABLE tasks ADD COLUMN parent_task_id INTEGER;
    END IF;
    
    -- Add split_task_id to tasks if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'tasks' AND column_name = 'split_task_id') THEN
        ALTER TABLE tasks ADD COLUMN split_task_id INTEGER;
    END IF;
    
    -- Add parent_task_id to partial_completions if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'partial_completions' AND column_name = 'parent_task_id') THEN
        ALTER TABLE partial_completions ADD COLUMN parent_task_id INTEGER;
    END IF;
    
    -- Add split_task_id to partial_completions if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'partial_completions' AND column_name = 'split_task_id') THEN
        ALTER TABLE partial_completions ADD COLUMN split_task_id INTEGER;
    END IF;
    
    -- Add parent_task_id to completion_history if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'completion_history' AND column_name = 'parent_task_id') THEN
        ALTER TABLE completion_history ADD COLUMN parent_task_id INTEGER;
    END IF;
    
    -- Add is_segment to completion_history if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'completion_history' AND column_name = 'is_segment') THEN
        ALTER TABLE completion_history ADD COLUMN is_segment BOOLEAN DEFAULT FALSE;
    END IF;
END $$;

-- Step 2: Fix existing tasks - set parent_task_id = id for base tasks (NULL parent)
UPDATE tasks
SET parent_task_id = id
WHERE parent_task_id IS NULL;

-- Step 3: Fix existing partial_completions - set parent_task_id from tasks table
UPDATE partial_completions pc
SET parent_task_id = t.parent_task_id,
    split_task_id = t.split_task_id
FROM tasks t
WHERE pc.task_id = t.id
  AND pc.user_id = t.user_id
  AND pc.parent_task_id IS NULL;

-- Step 4: For any orphaned partial_completions (task doesn't exist), set parent to task_id
UPDATE partial_completions
SET parent_task_id = task_id
WHERE parent_task_id IS NULL;

-- Step 5: Make parent_task_id NOT NULL in partial_completions (now that it's populated)
ALTER TABLE partial_completions
ALTER COLUMN parent_task_id SET NOT NULL;

-- Step 6: Fix existing completion_history entries
UPDATE completion_history ch
SET parent_task_id = t.parent_task_id
FROM tasks t
WHERE ch.task_id = t.id
  AND ch.user_id = t.user_id
  AND ch.parent_task_id IS NULL;

-- For orphaned completion_history, set parent to task_id
UPDATE completion_history
SET parent_task_id = task_id
WHERE parent_task_id IS NULL;

-- Make parent_task_id NOT NULL in completion_history
ALTER TABLE completion_history
ALTER COLUMN parent_task_id SET NOT NULL;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify tasks table structure
SELECT 
    'Tasks with NULL parent_task_id (should be 0):' as check_type,
    COUNT(*) as count
FROM tasks
WHERE parent_task_id IS NULL;

-- Verify base vs split tasks
SELECT 
    'Task type distribution:' as check_type,
    CASE 
        WHEN parent_task_id = id THEN 'Base Task'
        WHEN split_task_id IS NOT NULL THEN 'Split Segment'
        ELSE 'Unknown'
    END as task_type,
    COUNT(*) as count
FROM tasks
GROUP BY task_type;

-- Verify partial_completions
SELECT 
    'Partial completions with NULL parent_task_id (should be 0):' as check_type,
    COUNT(*) as count
FROM partial_completions
WHERE parent_task_id IS NULL;

-- Verify completion_history
SELECT 
    'Completion history with NULL parent_task_id (should be 0):' as check_type,
    COUNT(*) as count
FROM completion_history
WHERE parent_task_id IS NULL;

-- Show example of task relationships
SELECT 
    id,
    parent_task_id,
    split_task_id,
    LEFT(title, 60) as title_preview,
    completed,
    CASE 
        WHEN parent_task_id = id THEN 'Base'
        WHEN split_task_id IS NOT NULL THEN 'Segment ' || split_task_id
        ELSE 'Unknown'
    END as task_type
FROM tasks
ORDER BY parent_task_id, split_task_id
LIMIT 20;

-- ============================================================================
-- COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE tasks IS 'Student tasks from Canvas calendar. All tasks have parent_task_id set (self-referential for base tasks).';
COMMENT ON COLUMN tasks.parent_task_id IS 'REQUIRED: Self-referential (=id) for base tasks, references original task for segments';
COMMENT ON COLUMN tasks.split_task_id IS 'NULL for base tasks, 1,2,3... for segments of a split task';

COMMENT ON TABLE partial_completions IS 'Tracks accumulated time for partially completed tasks. IDs mirror the tasks table exactly.';
COMMENT ON COLUMN partial_completions.parent_task_id IS 'REQUIRED: Always matches the task.parent_task_id for grouping';
COMMENT ON COLUMN partial_completions.split_task_id IS 'Optional: Matches the task.split_task_id';

COMMENT ON TABLE completion_history IS 'Task completion data for AI learning. Segments are consolidated when all parts complete.';
COMMENT ON COLUMN completion_history.parent_task_id IS 'REQUIRED: Used to group and consolidate segment completions';
COMMENT ON COLUMN completion_history.is_segment IS 'TRUE for individual segment records, FALSE for consolidated parent record';

COMMENT ON TABLE session_state IS 'Saved study session state for resume capability';
COMMENT ON TABLE feedback IS 'User feedback, bug reports, and feature requests';
