-- OneSchool Global Study Planner - Database Schema
-- Run this in your Supabase SQL Editor

-- Users table
CREATE TABLE users (
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

-- Tasks table
CREATE TABLE tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    due_date TIMESTAMP NOT NULL,
    task_type VARCHAR(50),
    estimated_time INTEGER NOT NULL,
    user_estimate INTEGER,
    completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Schedules table (stores Study vs Lesson for each period)
CREATE TABLE schedules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    day VARCHAR(20) NOT NULL,
    period INTEGER NOT NULL,
    type VARCHAR(20) NOT NULL,
    UNIQUE(user_id, day, period)
);

-- Completion history (for AI learning)
CREATE TABLE completion_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    task_title VARCHAR(500),
    task_type VARCHAR(50),
    estimated_time INTEGER,
    actual_time INTEGER,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Session state table (for resume capability)
CREATE TABLE session_state (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(100) NOT NULL,
    day VARCHAR(20) NOT NULL,
    period INTEGER NOT NULL,
    remaining_time INTEGER NOT NULL,
    current_task_index INTEGER NOT NULL,
    task_start_time INTEGER NOT NULL,
    completions JSONB,
    saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);

-- Feedback table (for user feedback and bug reports)
CREATE TABLE feedback (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    feedback_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_tasks_user_id ON tasks(user_id);
CREATE INDEX idx_tasks_due_date ON tasks(due_date);
CREATE INDEX idx_tasks_completed ON tasks(completed);
CREATE INDEX idx_schedules_user_id ON schedules(user_id);
CREATE INDEX idx_completion_history_user_id ON completion_history(user_id);
CREATE INDEX idx_completion_history_type ON completion_history(task_type);
CREATE INDEX idx_session_state_user_id ON session_state(user_id);
CREATE INDEX idx_feedback_user_id ON feedback(user_id);
CREATE INDEX idx_feedback_created_at ON feedback(created_at);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to auto-update updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments for documentation
COMMENT ON TABLE users IS 'OneSchool Global student accounts';
COMMENT ON TABLE tasks IS 'Student tasks from Canvas calendar';
COMMENT ON TABLE schedules IS 'Weekly period schedule (Study vs Lesson)';
COMMENT ON TABLE completion_history IS 'Task completion data for AI learning';
COMMENT ON TABLE session_state IS 'Saved study session state for resume capability';
COMMENT ON TABLE feedback IS 'User feedback, bug reports, and feature requests';
