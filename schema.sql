-- ============================================================================
-- PlanAssist — Canonical Database Schema
-- OneSchool Global Study Planner
--
-- Safe to run against the live database: every statement uses
-- CREATE TABLE IF NOT EXISTS, ADD COLUMN IF NOT EXISTS, CREATE INDEX IF NOT
-- EXISTS, DROP COLUMN IF EXISTS, and DO $$ guards so nothing is duplicated
-- or destroyed. Edit this file for all future schema changes.
-- ============================================================================


-- ============================================================================
-- USERS
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id                          SERIAL PRIMARY KEY,
    email                       VARCHAR(255) UNIQUE NOT NULL,
    password                    VARCHAR(255) NOT NULL,
    name                        VARCHAR(255) NOT NULL,
    grade                       VARCHAR(50),
    canvas_api_token            TEXT,                           -- AES-256-GCM encrypted Canvas personal access token
    canvas_api_token_iv         TEXT,                           -- GCM initialisation vector
    present_periods             VARCHAR(20)     DEFAULT '2-6',  -- OSG periods the student attends (e.g. '2-6')
    is_new_user                 BOOLEAN         DEFAULT TRUE,   -- Cleared on first account setup save
    is_admin                    BOOLEAN         DEFAULT FALSE,
    is_banned                   BOOLEAN         DEFAULT FALSE,
    ban_reason                  TEXT,
    show_in_feed                BOOLEAN         DEFAULT TRUE,   -- Opt in/out of the Live Activity Feed
    schedule_enhanced           BOOLEAN         DEFAULT FALSE,  -- TRUE once the enhanced schedule is saved
    last_sync                   TIMESTAMP,                      -- Last successful Canvas sync timestamp
    -- Insignia system
    insignia_days               INTEGER         DEFAULT 0,      -- Distinct days the user completed >=1 task (never resets)
    insignia_selected           VARCHAR(30)     DEFAULT 'Default', -- Active insignia tier key
    -- Streak shields
    streak_shields_available    INTEGER         DEFAULT 0,
    streak_shield_mode          VARCHAR(10)     DEFAULT 'manual'
                                    CHECK (streak_shield_mode IN ('manual', 'automatic')),
    -- Credits currency
    credits                     INTEGER         NOT NULL DEFAULT 0,
    last_daily_chest            DATE,           -- Date (user local) of last chest claim — YYYY-MM-DD
    -- Campus & period offsets (replaces present_periods)
    campus                      VARCHAR(50)     DEFAULT 'Ashland',
    tz_periods                  VARCHAR(10)     DEFAULT '2-6',      -- Present periods
    -- Calendar preferences
    calendar_show_homeroom      BOOLEAN         DEFAULT FALSE,
    calendar_show_completed     BOOLEAN         DEFAULT TRUE,
    calendar_show_prev_week     BOOLEAN         DEFAULT FALSE,
    calendar_show_current_week  BOOLEAN         DEFAULT TRUE,
    calendar_show_next_week1    BOOLEAN         DEFAULT FALSE,
    calendar_show_next_week2    BOOLEAN         DEFAULT FALSE,
    calendar_show_weekends      BOOLEAN         DEFAULT TRUE,
    -- Timestamps
    created_at                  TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    -- Notification preferences
    notif_grades                BOOLEAN         NOT NULL DEFAULT TRUE,
    notif_announcements         BOOLEAN         NOT NULL DEFAULT TRUE,
    notif_discussions           BOOLEAN         NOT NULL DEFAULT TRUE,
    notif_messages              BOOLEAN         NOT NULL DEFAULT TRUE,
    notif_achievements          BOOLEAN         NOT NULL DEFAULT TRUE,
    notif_studios               BOOLEAN         NOT NULL DEFAULT TRUE
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS canvas_api_token           TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS canvas_api_token_iv        TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS present_periods            VARCHAR(20)  DEFAULT '2-6';
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_new_user                BOOLEAN      DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin                   BOOLEAN      DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned                  BOOLEAN      DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason                 TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS show_in_feed               BOOLEAN      DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS schedule_enhanced          BOOLEAN      DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_sync                  TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS insignia_days              INTEGER      DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS insignia_selected          VARCHAR(30)  DEFAULT 'Default';
ALTER TABLE users ADD COLUMN IF NOT EXISTS streak_shields_available   INTEGER      DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS streak_shield_mode         VARCHAR(10)  DEFAULT 'manual';
ALTER TABLE users ADD COLUMN IF NOT EXISTS credits                    INTEGER      NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_daily_chest           DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS campus                      VARCHAR(50)  DEFAULT 'Ashland';
ALTER TABLE users ADD COLUMN IF NOT EXISTS tz_periods                  VARCHAR(10)  DEFAULT '2-6';
ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_show_homeroom     BOOLEAN      DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_show_completed    BOOLEAN      DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_show_prev_week    BOOLEAN      DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_show_current_week BOOLEAN      DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_show_next_week1   BOOLEAN      DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_show_next_week2   BOOLEAN      DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS calendar_show_weekends     BOOLEAN      DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_grades               BOOLEAN      NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_announcements        BOOLEAN      NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_discussions          BOOLEAN      NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_messages             BOOLEAN      NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_achievements         BOOLEAN      NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_studios              BOOLEAN      NOT NULL DEFAULT TRUE;

ALTER TABLE users DROP COLUMN IF EXISTS canvas_url;
ALTER TABLE users DROP COLUMN IF EXISTS present_periods;
ALTER TABLE users DROP COLUMN IF EXISTS tz_periods_dst;
ALTER TABLE users DROP COLUMN IF EXISTS email_notifications;
ALTER TABLE users DROP COLUMN IF EXISTS calendar_today_centered;

CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_last_sync ON users(last_sync ASC NULLS FIRST);


-- ============================================================================
-- COURSES
-- Synced from Canvas enrolments. One row per user per Canvas course.
-- ============================================================================

CREATE TABLE IF NOT EXISTS courses (
    id                      SERIAL PRIMARY KEY,
    user_id                 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id               BIGINT,
    name                    VARCHAR(255) NOT NULL,
    course_code             VARCHAR(100),
    current_score           NUMERIC(10,2),
    current_grade           VARCHAR(50),
    final_score             NUMERIC(10,2),
    final_grade             VARCHAR(50),
    current_period_score    NUMERIC(10,2),
    current_period_grade    VARCHAR(50),
    grading_period_id       INTEGER,
    grading_period_title    TEXT,
    enrollment_id           BIGINT,
    zoom_number             TEXT,
    enabled                 BOOLEAN DEFAULT TRUE,
    manually_created        BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, course_id)
);

ALTER TABLE courses ADD COLUMN IF NOT EXISTS course_code          VARCHAR(100);
ALTER TABLE courses ADD COLUMN IF NOT EXISTS current_period_score NUMERIC(6,2);
ALTER TABLE courses ADD COLUMN IF NOT EXISTS current_period_grade VARCHAR(50);
ALTER TABLE courses ADD COLUMN IF NOT EXISTS grading_period_id    INTEGER;
ALTER TABLE courses ADD COLUMN IF NOT EXISTS grading_period_title TEXT;
ALTER TABLE courses ADD COLUMN IF NOT EXISTS enrollment_id        BIGINT;
ALTER TABLE courses ADD COLUMN IF NOT EXISTS zoom_number          TEXT;
ALTER TABLE courses ADD COLUMN IF NOT EXISTS enabled              BOOLEAN DEFAULT TRUE;
ALTER TABLE courses ADD COLUMN IF NOT EXISTS manually_created     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE courses ALTER COLUMN current_grade TYPE VARCHAR(50);
ALTER TABLE courses ALTER COLUMN final_grade    TYPE VARCHAR(50);
-- Allow course_id to be NULL for manually-created courses
ALTER TABLE courses ALTER COLUMN course_id DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_courses_user_id   ON courses(user_id);
CREATE INDEX IF NOT EXISTS idx_courses_course_id ON courses(course_id);


-- ============================================================================
-- ASSIGNMENT GROUPS
-- Canvas assignment groups with grade weights per course.
-- ============================================================================

CREATE TABLE IF NOT EXISTS assignment_groups (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id   BIGINT  NOT NULL,
    group_id    BIGINT  NOT NULL,
    name        VARCHAR(255) NOT NULL,
    weight      NUMERIC(5,2),
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, course_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_assignment_groups_user_id   ON assignment_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_assignment_groups_course_id ON assignment_groups(course_id);
CREATE INDEX IF NOT EXISTS idx_assignment_groups_group_id  ON assignment_groups(group_id);


-- ============================================================================
-- TASKS
-- Active assignments imported from Canvas. Supports split segments.
-- ============================================================================

CREATE TABLE IF NOT EXISTS tasks (
    id                      SERIAL PRIMARY KEY,
    user_id                 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Identity
    title                   VARCHAR(500) NOT NULL,
    segment                 VARCHAR(500),                   -- NULL for base tasks; e.g. 'Part 1' for splits
    class                   VARCHAR(200) NOT NULL,
    description             TEXT,
    url                     TEXT NOT NULL,
    -- Deadline
    deadline_date           DATE NOT NULL,
    deadline_time           TIME,                           -- NULL for date-only assignments
    -- Time
    estimated_time          INTEGER NOT NULL,               -- AI-estimated minutes
    user_estimated_time     INTEGER,                        -- User override (NULL = use estimated_time)
    accumulated_time        INTEGER DEFAULT 0,              -- Minutes logged so far (task still active)
    -- State flags
    completed               BOOLEAN DEFAULT FALSE,
    deleted                 BOOLEAN DEFAULT FALSE,          -- Ignored/checked off; preserved across syncs
    ignored                 BOOLEAN DEFAULT FALSE,          -- Explicitly ignored (shown in Resolved tab)
    is_new                  BOOLEAN DEFAULT FALSE,          -- Freshly imported; pending user acknowledgement
    session_active          BOOLEAN DEFAULT FALSE,          -- Timer is currently running
    session_heartbeat       TIMESTAMPTZ,                    -- Last heartbeat from an active timer (NULL if not in session)
    split_origin            BOOLEAN DEFAULT FALSE,          -- Original task before a split was performed
    manually_created        BOOLEAN DEFAULT FALSE,          -- Created manually, not from Canvas
    -- Canvas sync fields
    course_id               BIGINT,
    assignment_id           BIGINT,
    points_possible         NUMERIC(10,2),
    assignment_group_id     BIGINT,
    current_score           NUMERIC(10,2),
    current_grade           VARCHAR(50),
    grading_type            VARCHAR(50),                    -- 'points' | 'percent' | 'letter_grade' | 'gpa_scale' | 'pass_fail' | 'not_graded'
    grade_id                INTEGER,                        -- Monotonically increasing; used to detect new grade events
    unlock_at               TIMESTAMP,
    lock_at                 TIMESTAMP,
    submitted_at            TIMESTAMP,
    is_missing              BOOLEAN DEFAULT FALSE,
    is_late                 BOOLEAN DEFAULT FALSE,
    quiz_id                 BIGINT,                             -- Canvas classic quiz ID (NULL for standard assignments)
    inactive                BOOLEAN NOT NULL DEFAULT FALSE,     -- TRUE = removed/unpublished from Canvas; hidden in UI
    -- Timestamps
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, assignment_id)
);

ALTER TABLE tasks ADD COLUMN IF NOT EXISTS segment             VARCHAR(500);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS description         TEXT;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS deadline_date       DATE;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS deadline_time       TIME;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS user_estimated_time INTEGER;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS accumulated_time    INTEGER DEFAULT 0;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS ignored             BOOLEAN DEFAULT FALSE;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS is_new              BOOLEAN DEFAULT FALSE;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS session_active      BOOLEAN DEFAULT FALSE;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS session_heartbeat   TIMESTAMPTZ;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS split_origin        BOOLEAN DEFAULT FALSE;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS manually_created    BOOLEAN DEFAULT FALSE;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS course_id           BIGINT;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS assignment_id       BIGINT;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS points_possible     NUMERIC(10,2);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS assignment_group_id BIGINT;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS current_score       NUMERIC(10,2);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS current_grade       VARCHAR(50);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS grading_type        VARCHAR(50);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS grade_id            INTEGER;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS unlock_at           TIMESTAMP;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS lock_at             TIMESTAMP;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS submitted_at        TIMESTAMP;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS is_missing          BOOLEAN DEFAULT FALSE;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS is_late             BOOLEAN DEFAULT FALSE;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS quiz_id             BIGINT;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS inactive            BOOLEAN NOT NULL DEFAULT FALSE;

-- Widen NUMERIC columns to NUMERIC(10,2) to prevent overflow from large Canvas point values.
-- NUMERIC(6,2) caps at 9999.99 and NUMERIC(8,2) caps at 999999.99 — both reachable in
-- Canvas configs that store raw point totals rather than percentages.
-- TYPE change is safe on PostgreSQL (widening never truncates existing data).
ALTER TABLE courses       ALTER COLUMN current_score        TYPE NUMERIC(10,2);
ALTER TABLE courses       ALTER COLUMN final_score          TYPE NUMERIC(10,2);
ALTER TABLE courses       ALTER COLUMN current_period_score TYPE NUMERIC(10,2);
ALTER TABLE grade_history ALTER COLUMN score                TYPE NUMERIC(10,2);
ALTER TABLE grade_history ALTER COLUMN points_possible      TYPE NUMERIC(10,2);
ALTER TABLE tasks ALTER COLUMN current_grade TYPE VARCHAR(50);
ALTER TABLE tasks ALTER COLUMN grading_type   TYPE VARCHAR(50);
ALTER TABLE tasks DROP COLUMN IF EXISTS priority_order;
ALTER TABLE tasks DROP COLUMN IF EXISTS deadline;

CREATE INDEX IF NOT EXISTS idx_tasks_user_id          ON tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_title            ON tasks(title);
CREATE INDEX IF NOT EXISTS idx_tasks_class            ON tasks(class);
CREATE INDEX IF NOT EXISTS idx_tasks_url              ON tasks(url);
CREATE INDEX IF NOT EXISTS idx_tasks_deadline_date    ON tasks(deadline_date);
CREATE INDEX IF NOT EXISTS idx_tasks_completed        ON tasks(completed);
CREATE INDEX IF NOT EXISTS idx_tasks_deleted          ON tasks(deleted);
CREATE INDEX IF NOT EXISTS idx_tasks_is_new           ON tasks(is_new);
CREATE INDEX IF NOT EXISTS idx_tasks_segment          ON tasks(segment);
CREATE INDEX IF NOT EXISTS idx_tasks_assignment_id    ON tasks(assignment_id);
CREATE INDEX IF NOT EXISTS idx_tasks_quiz_id          ON tasks(quiz_id) WHERE quiz_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_inactive         ON tasks(user_id, inactive) WHERE inactive = TRUE;
CREATE INDEX IF NOT EXISTS idx_tasks_course_id        ON tasks(course_id);
CREATE INDEX IF NOT EXISTS idx_tasks_assignment_group ON tasks(assignment_group_id);
CREATE INDEX IF NOT EXISTS idx_tasks_session_active   ON tasks(user_id, session_active) WHERE session_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_tasks_user_grade_id    ON tasks(user_id, grade_id) WHERE grade_id IS NOT NULL;


-- ============================================================================
-- TASKS COMPLETED
-- Permanent record of completed tasks. Split segments may be consolidated.
-- ============================================================================

CREATE TABLE IF NOT EXISTS tasks_completed (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title           VARCHAR(500) NOT NULL,
    class           VARCHAR(200) NOT NULL,
    description     TEXT,
    url             TEXT NOT NULL,              -- Used to match and consolidate split segments
    deadline_date   DATE NOT NULL,
    deadline_time   TIME,
    estimated_time  INTEGER NOT NULL,           -- user_estimated_time if set, otherwise estimated_time
    actual_time     INTEGER NOT NULL,           -- Total minutes logged (sum across all segments for splits)
    completed_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE tasks_completed ADD COLUMN IF NOT EXISTS description   TEXT;
ALTER TABLE tasks_completed ADD COLUMN IF NOT EXISTS deadline_date DATE;
ALTER TABLE tasks_completed ADD COLUMN IF NOT EXISTS deadline_time TIME;
ALTER TABLE tasks_completed DROP COLUMN IF EXISTS deadline;

CREATE INDEX IF NOT EXISTS idx_tasks_completed_user_id      ON tasks_completed(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_url          ON tasks_completed(url);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_class        ON tasks_completed(class);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_title        ON tasks_completed(title);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_completed_at ON tasks_completed(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_completed_deadline     ON tasks_completed(deadline_date);


-- ============================================================================
-- TASK NOTES
-- Per-task user notes. One row per (task, user) pair.
-- ============================================================================

CREATE TABLE IF NOT EXISTS notes (
    task_id     INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    notes       TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (task_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_notes_task_id ON notes(task_id);
CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);


-- ============================================================================
-- SESSION PRIORITIES
-- Ordered task list for a user's focus session on a given date.
-- ============================================================================

CREATE TABLE IF NOT EXISTS session_priorities (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date        DATE NOT NULL,
    task_ids    JSONB NOT NULL DEFAULT '[]',
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, date)
);

CREATE INDEX IF NOT EXISTS idx_session_priorities_user_date ON session_priorities(user_id, date);


-- ============================================================================
-- AGENDAS
-- Structured work blocks with ordered rows of task + action + time budget.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agendas (
    id                      SERIAL PRIMARY KEY,
    user_id                 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL,
    rows                    JSONB NOT NULL DEFAULT '[]',    -- [{rowIndex, taskId, action, timeMins, zone?}]
    current_row             INTEGER NOT NULL DEFAULT 0,     -- 0-based index of the active row
    current_row_elapsed     INTEGER NOT NULL DEFAULT 0,     -- Seconds spent on current row's timer this session
    current_row_countdown   INTEGER,                        -- Seconds remaining on countdown (NULL = full timeMins)
    finished                BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE agendas ADD COLUMN IF NOT EXISTS rows                  JSONB   NOT NULL DEFAULT '[]';
ALTER TABLE agendas ADD COLUMN IF NOT EXISTS current_row           INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agendas ADD COLUMN IF NOT EXISTS current_row_elapsed   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agendas ADD COLUMN IF NOT EXISTS current_row_countdown INTEGER;
ALTER TABLE agendas DROP COLUMN IF EXISTS task_ids;

CREATE INDEX IF NOT EXISTS idx_agendas_user_id ON agendas(user_id);


-- ============================================================================
-- SCHEDULES
-- User's weekly timetable. One row per period per day.
-- ============================================================================

CREATE TABLE IF NOT EXISTS schedules (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day         VARCHAR(20) NOT NULL,
    period      INTEGER NOT NULL,
    type        VARCHAR(20) NOT NULL,
    course_id   INTEGER REFERENCES courses(id) ON DELETE SET NULL,
    course_name TEXT,
    UNIQUE(user_id, day, period)
);

ALTER TABLE schedules ADD COLUMN IF NOT EXISTS course_id   INTEGER REFERENCES courses(id) ON DELETE SET NULL;
ALTER TABLE schedules ADD COLUMN IF NOT EXISTS course_name TEXT;

CREATE INDEX IF NOT EXISTS idx_schedules_user_id ON schedules(user_id);


-- ============================================================================
-- ITINERARY SLOTS
-- Maps Study period slots on a specific date to an agenda.
-- ============================================================================

CREATE TABLE IF NOT EXISTS itinerary_slots (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date        DATE NOT NULL,
    period      INTEGER NOT NULL,
    agenda_id   INTEGER REFERENCES agendas(id) ON DELETE SET NULL,
    UNIQUE(user_id, date, period)
);

ALTER TABLE itinerary_slots DROP COLUMN IF EXISTS day;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'itinerary_slots_user_date_period_unique'
    ) THEN
        ALTER TABLE itinerary_slots
            ADD CONSTRAINT itinerary_slots_user_date_period_unique UNIQUE (user_id, date, period);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_itinerary_slots_user ON itinerary_slots(user_id);


-- ============================================================================
-- TUTORIALS
-- Booked tutorial sessions per date/period slot.
-- ============================================================================

CREATE TABLE IF NOT EXISTS tutorials (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date        DATE NOT NULL,
    period      INTEGER NOT NULL,
    zoom_number TEXT,
    topic       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, date, period)
);

ALTER TABLE tutorials DROP COLUMN IF EXISTS day;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tutorials_user_date_period_unique'
    ) THEN
        ALTER TABLE tutorials
            ADD CONSTRAINT tutorials_user_date_period_unique UNIQUE (user_id, date, period);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_tutorials_user ON tutorials(user_id);


-- ============================================================================
-- COMPLETION FEED
-- Live feed of recent Canvas task completions across opted-in users.
-- The insignia column is stored at completion time but the feed query
-- always joins users.insignia_selected live so the display is always current.
-- ============================================================================

CREATE TABLE IF NOT EXISTS completion_feed (
    id           SERIAL PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_name    VARCHAR(255) NOT NULL,
    user_grade   VARCHAR(50),
    task_title   VARCHAR(500) NOT NULL,
    task_class   VARCHAR(200) NOT NULL,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    insignia     VARCHAR(30) DEFAULT 'Default'
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'completion_feed' AND column_name = 'feed_label'
    ) THEN
        ALTER TABLE completion_feed RENAME COLUMN feed_label TO insignia;
    END IF;
END $$;

ALTER TABLE completion_feed ADD COLUMN IF NOT EXISTS insignia VARCHAR(30) DEFAULT 'Default';
ALTER TABLE completion_feed ALTER COLUMN insignia SET DEFAULT 'Default';
ALTER TABLE completion_feed ALTER COLUMN user_grade TYPE VARCHAR(50);

CREATE INDEX IF NOT EXISTS idx_completion_feed_completed_at ON completion_feed(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_completion_feed_user_id      ON completion_feed(user_id);


-- ============================================================================
-- FEED REACTIONS
-- Emoji reactions on completion feed entries. One per user per entry.
-- ============================================================================

CREATE TABLE IF NOT EXISTS feed_reactions (
    id                       SERIAL PRIMARY KEY,
    feed_entry_id            INTEGER NOT NULL REFERENCES completion_feed(id) ON DELETE CASCADE,
    user_id                  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji                    VARCHAR(10) NOT NULL,
    created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    credits_claimed          BOOLEAN NOT NULL DEFAULT FALSE, -- TRUE once the entry owner claimed credits
    UNIQUE(feed_entry_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_feed_reactions_entry ON feed_reactions(feed_entry_id);
CREATE INDEX IF NOT EXISTS idx_feed_reactions_user  ON feed_reactions(user_id);


-- ============================================================================
-- WEEKLY LEADERBOARD
-- Canvas-confirmed task completion counts by grade, reset each Monday.
-- ============================================================================

CREATE TABLE IF NOT EXISTS weekly_leaderboard (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_name       VARCHAR(255) NOT NULL,
    grade           VARCHAR(50) NOT NULL,
    tasks_completed INTEGER DEFAULT 0,
    spins_taken     INTEGER NOT NULL DEFAULT 0, -- spins used from this week's entry
    week_start      DATE NOT NULL,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, week_start)
);

ALTER TABLE weekly_leaderboard ALTER COLUMN grade TYPE VARCHAR(50);

CREATE INDEX IF NOT EXISTS idx_weekly_leaderboard_week_start      ON weekly_leaderboard(week_start DESC);
CREATE INDEX IF NOT EXISTS idx_weekly_leaderboard_grade           ON weekly_leaderboard(grade);
CREATE INDEX IF NOT EXISTS idx_weekly_leaderboard_tasks_completed ON weekly_leaderboard(tasks_completed DESC);


-- ============================================================================
-- INSIGNIA UNLOCKS
-- Records which insignia tiers each user has earned.
-- Tiers (days required): Default=0 Copper=2 Silver=5 Gold=10 Emerald=20
--                        Amethyst=30 Ruby=40 Diamond=50 Obsidian=75 Antimatter=100
-- ============================================================================

CREATE TABLE IF NOT EXISTS insignia_unlocks (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label       VARCHAR(30) NOT NULL,
    unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, label)
);

-- Rename from old table name if it still exists and the new one does not
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'feed_label_unlocks')
    AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'insignia_unlocks')
    THEN
        ALTER TABLE feed_label_unlocks RENAME TO insignia_unlocks;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_feed_label_unlocks_user') THEN
        ALTER INDEX idx_feed_label_unlocks_user RENAME TO idx_insignia_unlocks_user;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_insignia_unlocks_user ON insignia_unlocks(user_id);


-- ============================================================================
-- STREAK SHIELD LOG
-- One row per calendar day a streak shield was consumed.
-- ============================================================================

CREATE TABLE IF NOT EXISTS streak_shield_log (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    shield_date DATE NOT NULL,
    consumed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, shield_date)
);

CREATE INDEX IF NOT EXISTS idx_streak_shield_log_user ON streak_shield_log(user_id, shield_date DESC);


-- ============================================================================
-- USER BADGES (Gallery)
-- badge_key examples: first_completion, tasks_10, tasks_25, tasks_50,
--   tasks_100, tasks_250, tasks_500, streak_7, streak_14, streak_30
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_badges (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    badge_key   VARCHAR(60) NOT NULL,
    awarded_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, badge_key)
);

CREATE INDEX IF NOT EXISTS idx_user_badges_user ON user_badges(user_id);


-- ============================================================================
-- FEEDBACK
-- User-submitted feedback, bug reports, and feature requests.
-- ============================================================================

CREATE TABLE IF NOT EXISTS feedback (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_email      VARCHAR(255),
    user_name       VARCHAR(255),
    feedback_text   TEXT NOT NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feedback_user_id    ON feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback(created_at DESC);


-- ============================================================================
-- HELP CONTENT
-- Single-row table holding admin-editable help page markdown.
-- ============================================================================

CREATE TABLE IF NOT EXISTS help_content (
    id          INTEGER PRIMARY KEY DEFAULT 1,
    content     TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by  INTEGER REFERENCES users(id)
);

INSERT INTO help_content (id, content) VALUES (1, '')
ON CONFLICT (id) DO NOTHING;


-- ============================================================================
-- ANNOUNCEMENTS
-- Admin-created persistent banners shown to all or targeted users.
-- type:            'info' (dismissible, blue) | 'urgent' (non-dismissible, red)
-- target_audience: 'all' | 'existing' (before creation) | 'new' (after creation)
-- ============================================================================

CREATE TABLE IF NOT EXISTS announcements (
    id              SERIAL PRIMARY KEY,
    author_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    author_name     TEXT NOT NULL,
    message         TEXT NOT NULL,
    type            TEXT NOT NULL DEFAULT 'info'
                        CHECK (type IN ('info', 'urgent')),
    target_audience VARCHAR(20) NOT NULL DEFAULT 'all'
                        CHECK (target_audience IN ('all', 'existing', 'new')),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deactivated_at  TIMESTAMPTZ
);

ALTER TABLE announcements ADD COLUMN IF NOT EXISTS target_audience VARCHAR(20) DEFAULT 'all';


-- ============================================================================
-- ANNOUNCEMENT DISMISSALS
-- Tracks which dismissible announcements each user has already closed.
-- ============================================================================

CREATE TABLE IF NOT EXISTS announcement_dismissals (
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    announcement_id INTEGER NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
    dismissed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, announcement_id)
);


-- ============================================================================
-- ADMIN AUDIT LOG
-- Records all admin actions for accountability.
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id               SERIAL PRIMARY KEY,
    admin_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    admin_name       TEXT NOT NULL,
    action           TEXT NOT NULL,
    target_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_user_name TEXT,
    details          JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================================
-- TRIGGERS
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


-- ============================================================================
-- BACKFILLS
-- Safe one-time data corrections. All guarded so they are harmless on re-run.
-- ============================================================================

-- Backfill last_sync from MAX(tasks.created_at) for users who appear to never have synced
UPDATE users u
SET last_sync = (SELECT MAX(t.created_at) FROM tasks t WHERE t.user_id = u.id)
WHERE u.last_sync IS NULL;

-- Backfill insignia_days from distinct completion days (for users still at 0)
UPDATE users u
SET insignia_days = (
    SELECT COUNT(DISTINCT tc.completed_at::date)
    FROM tasks_completed tc
    WHERE tc.user_id = u.id
)
WHERE u.insignia_days = 0;

-- Backfill insignia_unlocks for all users from their current insignia_days (11-tier set)
DO $$
DECLARE
    tier_thresholds INT[]  := ARRAY[0, 2, 5, 10, 20, 30, 40, 50, 60, 80, 100];
    tier_labels     TEXT[] := ARRAY['Default','Bronze','Silver','Gold',
                                    'Emerald','Sapphire','Ruby','Amethyst',
                                    'Obsidian','Diamond','Antimatter'];
    rec RECORD;
    i   INT;
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

-- Remove stale rows for removed tiers (Platinum, Onyx) and any other invalid names
DELETE FROM insignia_unlocks
WHERE label NOT IN ('Default','Bronze','Silver','Gold',
                    'Emerald','Sapphire','Ruby','Amethyst',
                    'Obsidian','Diamond','Antimatter',
                    -- purchased insignias
                    'Meteorite','Dragonbone','Celestium','Aether','Soulstone',
                    'Starlight','Astral Crystal','Dark Matter','Neutronium','Singularity Core');

-- Rename old earned Aether → Antimatter (Aether is now a purchased insignia name)
-- Any existing Aether rows are from the old earned tier and should become Antimatter.
UPDATE insignia_unlocks SET label = 'Antimatter' WHERE label = 'Aether';
UPDATE users SET insignia_selected = 'Antimatter' WHERE insignia_selected = 'Aether';

-- Reset any remaining invalid insignia_selected values to Default
UPDATE users
SET insignia_selected = 'Default'
WHERE insignia_selected NOT IN (
  'Default','Bronze','Silver','Gold',
  'Emerald','Sapphire','Ruby','Amethyst',
  'Obsidian','Diamond','Antimatter',
  'Meteorite','Dragonbone','Celestium','Aether','Soulstone',
  'Starlight','Astral Crystal','Dark Matter','Neutronium','Singularity Core'
);

-- Backfill first_completion gallery badge
INSERT INTO user_badges (user_id, badge_key, awarded_at)
SELECT user_id, 'first_completion', MIN(completed_at)
FROM tasks_completed
GROUP BY user_id
ON CONFLICT DO NOTHING;

-- Backfill task-count gallery badges (10, 25, 50, 100, 250, 500)
DO $$
DECLARE
    thresholds INT[] := ARRAY[10, 25, 50, 100, 250, 500];
    t          INT;
    rec        RECORD;
    aw         TIMESTAMP;
BEGIN
    FOR rec IN SELECT user_id, COUNT(*) AS total FROM tasks_completed GROUP BY user_id LOOP
        FOREACH t IN ARRAY thresholds LOOP
            IF rec.total >= t THEN
                SELECT completed_at INTO aw
                FROM (
                    SELECT completed_at FROM tasks_completed
                    WHERE user_id = rec.user_id
                    ORDER BY completed_at ASC LIMIT t
                ) sub
                ORDER BY completed_at DESC LIMIT 1;
                INSERT INTO user_badges (user_id, badge_key, awarded_at)
                VALUES (rec.user_id, 'tasks_' || t, aw)
                ON CONFLICT DO NOTHING;
            END IF;
        END LOOP;
    END LOOP;
END $$;

-- ============================================================================
-- BACKFILL: Fix streak_shield_log.shield_date to match campus-tz date of consumed_at
-- The streak system uses consumed_at (UTC timestamp) for all calculations.
-- shield_date is only used as the unique conflict key — it must match consumed_at's
-- campus-tz date so future inserts don't produce false conflicts.
-- ============================================================================
UPDATE streak_shield_log ssl
SET shield_date = (
    ssl.consumed_at AT TIME ZONE 'UTC'
    AT TIME ZONE (
        CASE (SELECT campus FROM users WHERE id = ssl.user_id)
            WHEN 'Calgary'        THEN 'America/Edmonton'
            WHEN 'Edmonton'       THEN 'America/Edmonton'
            WHEN 'Kalispell'      THEN 'America/Denver'
            WHEN 'Los Angeles'    THEN 'America/Los_Angeles'
            WHEN 'Maple Creek'    THEN 'America/Regina'
            WHEN 'Oxbow'          THEN 'America/Regina'
            WHEN 'Portland'       THEN 'America/Los_Angeles'
            WHEN 'Regina'         THEN 'America/Regina'
            WHEN 'San Francisco'  THEN 'America/Los_Angeles'
            WHEN 'Seattle'        THEN 'America/Los_Angeles'
            WHEN 'Vancouver'      THEN 'America/Los_Angeles'
            WHEN 'Chicago'        THEN 'America/Chicago'
            WHEN 'Council Bluffs' THEN 'America/Chicago'
            WHEN 'Des Moines'     THEN 'America/Chicago'
            WHEN 'Gothenburg'     THEN 'America/Chicago'
            WHEN 'Jamaica'        THEN 'America/Jamaica'
            WHEN 'Minneapolis'    THEN 'America/Chicago'
            WHEN 'Pembina'        THEN 'America/Chicago'
            WHEN 'Redwood Falls'  THEN 'America/Chicago'
            WHEN 'San Antonio'    THEN 'America/Chicago'
            WHEN 'Stonewall'      THEN 'America/Chicago'
            WHEN 'Barbados'       THEN 'America/Barbados'
            WHEN 'St. Vincent'    THEN 'America/St_Vincent'
            WHEN 'Trinidad'       THEN 'America/Port_of_Spain'
            ELSE 'America/New_York'
        END
    )
)::date;

-- ============================================================================
-- HPT USERS
-- High Performing Team (teacher/staff) accounts. Separate from student users.
-- Passcode is stored as bcrypt hash. Name is the teacher's display name.
-- ============================================================================

CREATE TABLE IF NOT EXISTS hpt_users (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    passcode_hash   VARCHAR(255) NOT NULL,          -- bcrypt hash of the teacher passcode
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hpt_users_name ON hpt_users(name);


-- ============================================================================
-- HPT STUDIOS
-- A Studio is a group of students that an HPT user monitors.
-- setup_type: 'course' = derived live from courses.course_id
--             'key'    = students join manually with a studio_key
-- ============================================================================

CREATE TABLE IF NOT EXISTS hpt_studios (
    id              SERIAL PRIMARY KEY,
    studio_key      VARCHAR(20)  NOT NULL UNIQUE,   -- Short unique code (always set; auto-gen for both types)
    setup_type      VARCHAR(10)  NOT NULL DEFAULT 'course'
                        CHECK (setup_type IN ('course', 'key')),
    course_id       BIGINT,                         -- Set for 'course' type; NULL for 'key' type
    name            VARCHAR(255) NOT NULL,           -- Studio display name
    color           VARCHAR(30)  NOT NULL DEFAULT '#7C3AED', -- Hex color for the studio card
    zoom_number     TEXT,                            -- Optional zoom number
    created_by      INTEGER NOT NULL REFERENCES hpt_users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hpt_studios_course_id   ON hpt_studios(course_id);
CREATE INDEX IF NOT EXISTS idx_hpt_studios_created_by  ON hpt_studios(created_by);
CREATE INDEX IF NOT EXISTS idx_hpt_studios_studio_key  ON hpt_studios(studio_key);


-- ============================================================================
-- HPT STUDIO MEMBERS
-- Explicit members for 'key'-type studios.
-- 'course'-type studios derive members live from the courses table.
-- ============================================================================

CREATE TABLE IF NOT EXISTS hpt_studio_members (
    id          SERIAL PRIMARY KEY,
    studio_id   INTEGER NOT NULL REFERENCES hpt_studios(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    unread      BOOLEAN NOT NULL DEFAULT FALSE,   -- TRUE = new studio join, show in Alerts tab
    UNIQUE(studio_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_hpt_studio_members_studio ON hpt_studio_members(studio_id);
CREATE INDEX IF NOT EXISTS idx_hpt_studio_members_user   ON hpt_studio_members(user_id);
ALTER TABLE hpt_studio_members ADD COLUMN IF NOT EXISTS unread BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_hpt_studio_members_unread ON hpt_studio_members(user_id, unread) WHERE unread = TRUE;


-- ============================================================================
-- HPT STUDIO SHARES
-- HPT users that have been given shared access to a studio.
-- ============================================================================

CREATE TABLE IF NOT EXISTS hpt_studio_shares (
    id          SERIAL PRIMARY KEY,
    studio_id   INTEGER NOT NULL REFERENCES hpt_studios(id) ON DELETE CASCADE,
    hpt_user_id INTEGER NOT NULL REFERENCES hpt_users(id) ON DELETE CASCADE,
    shared_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(studio_id, hpt_user_id)
);

CREATE INDEX IF NOT EXISTS idx_hpt_studio_shares_studio   ON hpt_studio_shares(studio_id);
CREATE INDEX IF NOT EXISTS idx_hpt_studio_shares_hpt_user ON hpt_studio_shares(hpt_user_id);


-- ============================================================================
-- HPT STUDIO BANNERS
-- Dismissible banners posted by HPT users, shown to members on the Hub.
-- ============================================================================

CREATE TABLE IF NOT EXISTS hpt_studio_banners (
    id          SERIAL PRIMARY KEY,
    studio_id   INTEGER NOT NULL REFERENCES hpt_studios(id) ON DELETE CASCADE,
    message     TEXT NOT NULL,
    author_name VARCHAR(255) NOT NULL,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hpt_studio_banners_studio ON hpt_studio_banners(studio_id);
CREATE INDEX IF NOT EXISTS idx_hpt_studio_banners_active ON hpt_studio_banners(is_active);


-- ============================================================================
-- HPT STUDIO BANNER DISMISSALS
-- Tracks which users have dismissed which studio banners.
-- ============================================================================

CREATE TABLE IF NOT EXISTS hpt_studio_banner_dismissals (
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    banner_id   INTEGER NOT NULL REFERENCES hpt_studio_banners(id) ON DELETE CASCADE,
    dismissed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, banner_id)
);


-- ============================================================================
-- GRADE HISTORY TABLE
-- Stores all graded Canvas submissions for a user, keyed by (user_id, assignment_id).
-- Populated by Grade Sync (2-month window); upserts on conflict — no duplicates.
-- graded_at: Canvas graded_at timestamp; falls back to submitted_at when absent.
-- unread:    TRUE = entry is new/changed and should appear in the notification sidebar.
--            First-run guard in server.js sets unread=FALSE for brand-new users so their
--            entire grade history doesn't flood in as notifications on first load.
-- ============================================================================
CREATE TABLE IF NOT EXISTS grade_history (
    id               SERIAL PRIMARY KEY,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id        BIGINT  NOT NULL,
    assignment_id    BIGINT  NOT NULL,
    title            TEXT    NOT NULL,
    course_name      TEXT,
    html_url         TEXT,
    score            NUMERIC(10,2),
    points_possible  NUMERIC(10,2),
    grade            VARCHAR(50),
    grading_type     VARCHAR(50) DEFAULT 'points',
    submitted_at     TIMESTAMPTZ,
    graded_at        TIMESTAMPTZ,
    synced_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    unread           BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (user_id, assignment_id)
);

-- Safe migrations for existing tables (no-ops if columns already exist)
ALTER TABLE grade_history ADD COLUMN IF NOT EXISTS graded_at TIMESTAMPTZ;
ALTER TABLE grade_history ADD COLUMN IF NOT EXISTS unread    BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_grade_history_user_id    ON grade_history(user_id);
CREATE INDEX IF NOT EXISTS idx_grade_history_synced_at  ON grade_history(user_id, synced_at DESC);
CREATE INDEX IF NOT EXISTS idx_grade_history_graded_at  ON grade_history(user_id, graded_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_grade_history_unread     ON grade_history(user_id, unread) WHERE unread = TRUE;

-- unread flag on insignia_unlocks — TRUE = show in notification sidebar
-- New entries inserted by server.js default to FALSE for first-run users.
ALTER TABLE insignia_unlocks ADD COLUMN IF NOT EXISTS unread BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_insignia_unlocks_unread ON insignia_unlocks(user_id, unread) WHERE unread = TRUE;

-- unread flag on user_badges
ALTER TABLE user_badges ADD COLUMN IF NOT EXISTS unread BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_user_badges_unread ON user_badges(user_id, unread) WHERE unread = TRUE;

-- ============================================================================
-- CANVAS ACTIVITY CACHE
-- Stores Canvas announcements, discussions, and messages per user.
-- Fed by Activity Refresh; deduped by (user_id, type, link_url).
-- unread = TRUE means the item is new/updated since last seen.
-- event_at is the canonical sort timestamp: posted_at / last_reply_at / updated_at.
-- ============================================================================
CREATE TABLE IF NOT EXISTS canvas_activity (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        VARCHAR(20) NOT NULL CHECK (type IN ('announcement','discussion','message')),
    canvas_id   BIGINT,
    title       TEXT NOT NULL,
    body        TEXT,
    course_name TEXT,
    link_url    TEXT,
    event_at    TIMESTAMPTZ NOT NULL,
    unread      BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(user_id, type, link_url)
);

CREATE INDEX IF NOT EXISTS idx_canvas_activity_user_type ON canvas_activity(user_id, type);
CREATE INDEX IF NOT EXISTS idx_canvas_activity_event_at  ON canvas_activity(user_id, event_at DESC);
CREATE INDEX IF NOT EXISTS idx_canvas_activity_unread    ON canvas_activity(user_id, unread) WHERE unread = TRUE;

-- ============================================================================
-- NOTIFICATIONS (legacy) — dropped; notification logic now uses unread flags
-- on grade_history, insignia_unlocks, user_badges, and canvas_activity.
-- DROP is safe to re-run (IF EXISTS).  CASCADE removes dependent indexes.
-- ============================================================================
DROP TABLE IF EXISTS notifications CASCADE;

-- ============================================================================
-- CREDITS SYSTEM
-- ============================================================================

-- ALTER TABLE migrations for live DB (no-ops if columns already exist)
ALTER TABLE users             ADD COLUMN IF NOT EXISTS credits          INTEGER  NOT NULL DEFAULT 0;
ALTER TABLE users             ADD COLUMN IF NOT EXISTS last_daily_chest DATE;
ALTER TABLE weekly_leaderboard ADD COLUMN IF NOT EXISTS spins_taken     INTEGER  NOT NULL DEFAULT 0;
ALTER TABLE feed_reactions    ADD COLUMN IF NOT EXISTS credits_claimed  BOOLEAN  NOT NULL DEFAULT FALSE;

-- ============================================================================
-- INSIGNIA SHOP
-- Purchased insignias. One row per available insignia for sale.
-- Users unlock a purchased insignia when a row exists in insignia_unlocks
-- for them with the matching label (inserted by the purchase endpoint).
-- ============================================================================
CREATE TABLE IF NOT EXISTS insignia_shop (
    id          SERIAL PRIMARY KEY,
    label       VARCHAR(50) NOT NULL UNIQUE,
    cost        INTEGER NOT NULL,            -- credit cost
    description TEXT,
    sort_order  INTEGER NOT NULL DEFAULT 0
);

-- Seed the shop (INSERT … ON CONFLICT DO NOTHING is safe to re-run)
INSERT INTO insignia_shop (label, cost, description, sort_order) VALUES
  ('Meteorite',       1000, 'Dark brown with pulsing orange ember spots.',                      1),
  ('Dragonbone',      1000, 'Fades from white to pitch black and back, with a subtle jitter.',  2),
  ('Celestium',       1500, 'Shifts between red, purple, and blue with a pulsing ripple.',      3),
  ('Aether',          1500, 'Violent lightning-like purple lines flash across a purple base.',  4),
  ('Soulstone',       1500, 'Tan and brown letters that each teeters uniquely.',                5),
  ('Starlight',       1500, 'Letters blink and shake against pure black.',                      6),
  ('Astral Crystal',  2000, 'Opaque white letters that randomly glitch and vanish.',            7),
  ('Dark Matter',     2000, 'All-black letters that jitter violently and drift from side to side.', 8),
  ('Neutronium',      2500, 'Glowing neon green with a violent shutter effect.',                9),
  ('Singularity Core',2500, 'White and cyan letters with purple flames rising from each one.', 10)
ON CONFLICT (label) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_insignia_shop_sort ON insignia_shop(sort_order);
