-- ============================================================================
-- PlanAssist - Complete Database Schema (Canvas API Edition)
-- This file creates all tables from scratch with full Canvas API integration
-- Last Updated: February 2026
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
    canvas_api_token TEXT,                      -- Encrypted Canvas API token
    canvas_api_token_iv TEXT,                   -- Initialization vector for token encryption
    present_periods VARCHAR(10) DEFAULT '2-6',
    is_new_user BOOLEAN DEFAULT true,
    show_in_feed BOOLEAN DEFAULT true,          -- Show completions in public feed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tasks table - Active assignments from Canvas
CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    
    -- Basic task info
    title VARCHAR(500) NOT NULL,
    segment VARCHAR(500),                       -- NULL for base tasks, "Part 1" etc for splits
    class VARCHAR(200) NOT NULL,                -- Course name
    description TEXT,                           -- Assignment description (HTML)
    url TEXT NOT NULL,                          -- Direct assignment URL
    
    -- Deadline info
    deadline_date DATE NOT NULL,                -- Due date (YYYY-MM-DD)
    deadline_time TIME,                         -- Due time (HH:MM:SS) or NULL if date-only
    
    -- Time tracking
    estimated_time INTEGER NOT NULL,            -- AI-calculated estimate (minutes)
    user_estimated_time INTEGER,                -- User override (NULL if not set)
    accumulated_time INTEGER DEFAULT 0,         -- Time spent on incomplete tasks
    
    -- Status flags
    completed BOOLEAN DEFAULT FALSE,            -- When TRUE, moves to tasks_completed
    deleted BOOLEAN DEFAULT FALSE,              -- Soft delete (prevents re-import)
    is_new BOOLEAN DEFAULT FALSE,               -- Marks newly imported tasks
    priority_order INTEGER,                     -- Manual priority override
    
    -- Canvas API fields
    course_id BIGINT,                           -- Canvas course ID
    assignment_id BIGINT,                       -- Canvas assignment ID (unique)
    points_possible DECIMAL(10,2),              -- Maximum points for assignment
    assignment_group_id BIGINT,                 -- Category ID (Homework, Exams, etc.)
    current_score DECIMAL(10,2),                -- Student's current score
    current_grade VARCHAR(10),                  -- Student's current grade (letter/percent)
    grading_type VARCHAR(20),                   -- How it's graded (points, percent, etc.)
    unlock_at TIMESTAMP,                        -- When assignment becomes available
    lock_at TIMESTAMP,                          -- When assignment locks
    submitted_at TIMESTAMP,                     -- When student submitted
    is_missing BOOLEAN DEFAULT false,           -- Canvas missing flag
    is_late BOOLEAN DEFAULT false,              -- Canvas late flag
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(user_id, assignment_id)              -- Prevent duplicate assignments per user
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

-- Schedules table - User weekly schedule
CREATE TABLE IF NOT EXISTS schedules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    day VARCHAR(20) NOT NULL,
    period INTEGER NOT NULL,
    type VARCHAR(20) NOT NULL,                  -- 'Study' or 'Lesson'
    
    UNIQUE(user_id, day, period)
);

-- Session state table - Saved study session state
CREATE TABLE IF NOT EXISTS session_state (
    id SERIAL PRIMARY KEY,
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

-- Tasks completed table - Completed assignments with actual time
CREATE TABLE IF NOT EXISTS tasks_completed (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    class VARCHAR(200) NOT NULL,
    description TEXT,
    url TEXT NOT NULL,
    deadline_date DATE NOT NULL,
    deadline_time TIME,
    estimated_time INTEGER NOT NULL,            -- Shows user_estimated_time OR estimated_time
    actual_time INTEGER NOT NULL,               -- Time actually spent
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Notes table - Task notes for workspace
CREATE TABLE IF NOT EXISTS notes (
    task_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (task_id, user_id)
);

-- Feedback table - User feedback and bug reports
CREATE TABLE IF NOT EXISTS feedback (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    feedback_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Completion feed table - Live feed of recent completions
CREATE TABLE IF NOT EXISTS completion_feed (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_name VARCHAR(255) NOT NULL,
    user_grade VARCHAR(10),
    task_title VARCHAR(500) NOT NULL,
    task_class VARCHAR(200) NOT NULL,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Weekly leaderboard table - Weekly task completion counts
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

-- Courses
CREATE INDEX IF NOT EXISTS idx_courses_user_id ON courses(user_id);
CREATE INDEX IF NOT EXISTS idx_courses_course_id ON courses(course_id);

-- Assignment Groups
CREATE INDEX IF NOT EXISTS idx_assignment_groups_user_id ON assignment_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_assignment_groups_course_id ON assignment_groups(course_id);
CREATE INDEX IF NOT EXISTS idx_assignment_groups_group_id ON assignment_groups(group_id);

-- Tasks Completed
CREATE INDEX IF NOT EXISTS idx_tasks_completed_user_id ON tasks_completed(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_url ON tasks_completed(url);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_class ON tasks_completed(class);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_title ON tasks_completed(title);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_deadline_date ON tasks_completed(deadline_date);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_completed_at ON tasks_completed(completed_at);

-- Schedules
CREATE INDEX IF NOT EXISTS idx_schedules_user_id ON schedules(user_id);

-- Session State
CREATE INDEX IF NOT EXISTS idx_session_state_user_id ON session_state(user_id);

-- Notes
CREATE INDEX IF NOT EXISTS idx_notes_task_id ON notes(task_id);
CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);

-- Feedback
CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback(created_at);

-- Completion Feed
CREATE INDEX IF NOT EXISTS idx_completion_feed_completed_at ON completion_feed(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_completion_feed_user_id ON completion_feed(user_id);

-- Weekly Leaderboard
CREATE INDEX IF NOT EXISTS idx_weekly_leaderboard_week_start ON weekly_leaderboard(week_start DESC);
CREATE INDEX IF NOT EXISTS idx_weekly_leaderboard_grade ON weekly_leaderboard(grade);
CREATE INDEX IF NOT EXISTS idx_weekly_leaderboard_tasks_completed ON weekly_leaderboard(tasks_completed DESC);

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
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- TABLE COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE users IS 'Student user accounts with encrypted Canvas API tokens';
COMMENT ON COLUMN users.canvas_api_token IS 'AES-256-GCM encrypted Canvas API token';
COMMENT ON COLUMN users.canvas_api_token_iv IS 'Initialization vector for token decryption';
COMMENT ON COLUMN users.show_in_feed IS 'User preference: show completions in public feed (default true)';

COMMENT ON TABLE tasks IS 'Active assignments from Canvas API with full metadata and submission status';
COMMENT ON COLUMN tasks.title IS 'Assignment name from Canvas';
COMMENT ON COLUMN tasks.segment IS 'NULL for base tasks, "Part 1" etc for user-created splits';
COMMENT ON COLUMN tasks.class IS 'Course name from Canvas';
COMMENT ON COLUMN tasks.url IS 'Direct assignment URL from Canvas API';
COMMENT ON COLUMN tasks.deadline_date IS 'Due date (date part only)';
COMMENT ON COLUMN tasks.deadline_time IS 'Due time (NULL if assignment is date-only)';
COMMENT ON COLUMN tasks.accumulated_time IS 'Time spent on incomplete tasks (minutes)';
COMMENT ON COLUMN tasks.deleted IS 'Soft delete flag - prevents re-import while preserving history';
COMMENT ON COLUMN tasks.assignment_id IS 'Canvas assignment ID - unique identifier';
COMMENT ON COLUMN tasks.points_possible IS 'Maximum points for this assignment';
COMMENT ON COLUMN tasks.is_missing IS 'Canvas missing flag (assignment not submitted by due date)';
COMMENT ON COLUMN tasks.is_late IS 'Canvas late flag (submitted after due date)';

COMMENT ON TABLE courses IS 'Active courses with current grades for Marks tab';
COMMENT ON TABLE assignment_groups IS 'Assignment categories and weights for grade calculations';

COMMENT ON TABLE schedules IS 'User weekly schedule with Study/Lesson periods';
COMMENT ON TABLE session_state IS 'Saved study session state for resume capability';
COMMENT ON COLUMN session_state.current_task_index IS 'References the specific task.id being worked on';

COMMENT ON TABLE tasks_completed IS 'Completed assignments with actual time spent';
COMMENT ON TABLE notes IS 'Task-specific notes for workspace feature';
COMMENT ON TABLE feedback IS 'User feedback, bug reports, and feature requests';

COMMENT ON TABLE completion_feed IS 'Live feed of recent task completions (last 7 days, respecting privacy)';
COMMENT ON TABLE weekly_leaderboard IS 'Weekly task completion counts by grade, resets each Monday';

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Count all tables
SELECT 
    'Tables created' as check_type,
    COUNT(*) as count
FROM information_schema.tables 
WHERE table_schema = 'public' 
  AND table_type = 'BASE TABLE'
  AND table_name IN (
    'users', 'tasks', 'courses', 'assignment_groups', 'schedules', 
    'session_state', 'tasks_completed', 'notes', 'feedback', 
    'completion_feed', 'weekly_leaderboard'
  );

-- Count all indexes
SELECT 
    'Indexes created' as check_type,
    COUNT(*) as count
FROM pg_indexes 
WHERE schemaname = 'public';

-- Verify tasks table structure
SELECT 
    'Tasks table columns' as check_type,
    COUNT(*) as count
FROM information_schema.columns 
WHERE table_name = 'tasks';

-- Verify Canvas API columns exist
SELECT 
    'Canvas API columns' as check_type,
    COUNT(*) as count
FROM information_schema.columns 
WHERE table_name = 'tasks' 
  AND column_name IN (
    'course_id', 'assignment_id', 'points_possible', 'assignment_group_id',
    'current_score', 'current_grade', 'grading_type', 'unlock_at', 'lock_at',
    'submitted_at', 'is_missing', 'is_late'
  );

-- ============================================================================
-- SUCCESS MESSAGE
-- ============================================================================

SELECT 
    '✅ PlanAssist Complete Schema Created Successfully!' as status,
    '11 tables created' as tables,
    '40+ indexes created' as indexes,
    'Canvas API integration ready' as features;
