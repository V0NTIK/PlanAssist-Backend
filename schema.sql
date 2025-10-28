-- OneSchool Global Study Planner - Database Schema (FIXED v3)
-- CRITICAL FIX: Removed foreign key constraint on partial_completions.task_id
-- This allows partial completions to be saved even when task doesn't exist in tasks table

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

-- Tasks table (unchanged)
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

-- FIXED: Partial completions table - NO foreign key on task_id!
CREATE TABLE IF NOT EXISTS partial_completions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL,  -- ← CHANGED: No REFERENCES constraint!
    task_title VARCHAR(500) NOT NULL,
    accumulated_time INTEGER NOT NULL DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, task_id)
);

DROP TRIGGER IF EXISTS update_partial_completions_updated_at ON partial_completions;

-- Completion history (for AI learning)
CREATE TABLE IF NOT EXISTS completion_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    task_id INTEGER,
    task_title VARCHAR(500),
    task_type VARCHAR(50),
    estimated_time INTEGER,
    actual_time INTEGER,
    parent_task_title VARCHAR(500),
    is_segment BOOLEAN DEFAULT FALSE,
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

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_due_date ON tasks(due_date);
CREATE INDEX IF NOT EXISTS idx_tasks_completed ON tasks(completed);
CREATE INDEX IF NOT EXISTS idx_tasks_priority_order ON tasks(priority_order);
CREATE INDEX IF NOT EXISTS idx_tasks_is_new ON tasks(is_new);
CREATE INDEX IF NOT EXISTS idx_schedules_user_id ON schedules(user_id);
CREATE INDEX IF NOT EXISTS idx_partial_completions_user_id ON partial_completions(user_id);
CREATE INDEX IF NOT EXISTS idx_partial_completions_task_id ON partial_completions(task_id);
CREATE INDEX IF NOT EXISTS idx_completion_history_user_id ON completion_history(user_id);
CREATE INDEX IF NOT EXISTS idx_completion_history_type ON completion_history(task_type);
CREATE INDEX IF NOT EXISTS idx_completion_history_parent_title ON completion_history(parent_task_title);
CREATE INDEX IF NOT EXISTS idx_session_state_user_id ON session_state(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback(created_at);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to auto-update updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger for partial_completions last_updated
DROP TRIGGER IF EXISTS update_partial_completions_updated_at ON partial_completions;
CREATE TRIGGER update_partial_completions_updated_at BEFORE UPDATE ON partial_completions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments for documentation
COMMENT ON TABLE users IS 'OneSchool Global student accounts';
COMMENT ON TABLE tasks IS 'Student tasks from Canvas calendar';
COMMENT ON TABLE schedules IS 'Weekly period schedule (Study vs Lesson)';
COMMENT ON TABLE partial_completions IS 'Tracks accumulated time for partially completed tasks. NO foreign key on task_id to allow orphaned entries.';
COMMENT ON TABLE completion_history IS 'Task completion data for AI learning, includes segment tracking';
COMMENT ON TABLE session_state IS 'Saved study session state for resume capability';
COMMENT ON TABLE feedback IS 'User feedback, bug reports, and feature requests';
COMMENT ON COLUMN partial_completions.task_id IS 'Task ID (no foreign key constraint - allows saving even if task deleted)';
