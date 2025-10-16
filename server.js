// OneSchool Global Study Planner - Backend API (ENHANCED)
// server.js

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const axios = require('axios');
const ical = require('node-ical');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: [
    'https://planassist.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize session_state table if it doesn't exist
pool.query(`
  CREATE TABLE IF NOT EXISTS session_state (
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
  )
`).catch(err => console.error('Error creating session_state table:', err));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-key';

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Helper: Extract name from email
const extractNameFromEmail = (email) => {
  const username = email.split('@')[0];
  const parts = username.split('.');
  const first = parts[0].charAt(0).toUpperCase() + parts[0].slice(1);
  const last = parts[1] ? parts[1].replace(/\d+/g, '') : '';
  const lastName = last ? last.charAt(0).toUpperCase() + last.slice(1) : '';
  return `${first} ${lastName}`.trim();
};

// Validate OneSchool email
const isValidOneSchoolEmail = (email) => {
  return email.endsWith('@na.oneschoolglobal.com');
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!isValidOneSchoolEmail(email)) {
      return res.status(400).json({ error: 'Email must be in format: first.last##@na.oneschoolglobal.com' });
    }

    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const name = extractNameFromEmail(email);

    const result = await pool.query(
      'INSERT INTO users (email, password, name, is_new_user) VALUES ($1, $2, $3, $4) RETURNING id, email, name, is_new_user',
      [email, hashedPassword, name, true]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    res.json({ 
      token, 
      user: { 
        id: user.id, 
        email: user.email, 
        name: user.name,
        isNewUser: user.is_new_user
      } 
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!isValidOneSchoolEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    res.json({ 
      token, 
      user: { 
        id: user.id, 
        email: user.email, 
        name: user.name,
        isNewUser: user.is_new_user
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ============ ACCOUNT SETUP ROUTES ============

// Get account setup
app.get('/api/account/setup', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT grade, canvas_url, present_periods FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    const scheduleResult = await pool.query(
      'SELECT day, period, type FROM schedules WHERE user_id = $1',
      [req.user.id]
    );

    const schedule = {};
    scheduleResult.rows.forEach(row => {
      if (!schedule[row.day]) schedule[row.day] = {};
      schedule[row.day][row.period] = row.type;
    });

    res.json({
      grade: user.grade,
      canvasUrl: user.canvas_url,
      presentPeriods: user.present_periods,
      schedule
    });
  } catch (error) {
    console.error('Get account setup error:', error);
    res.status(500).json({ error: 'Failed to get account setup' });
  }
});

// Save account setup
app.post('/api/account/setup', authenticateToken, async (req, res) => {
  try {
    const { grade, canvasUrl, presentPeriods, schedule } = req.body;

    await pool.query(
      'UPDATE users SET grade = $1, canvas_url = $2, present_periods = $3, is_new_user = false WHERE id = $4',
      [grade, canvasUrl, presentPeriods, req.user.id]
    );

    await pool.query('DELETE FROM schedules WHERE user_id = $1', [req.user.id]);

    const insertPromises = [];
    for (const [day, periods] of Object.entries(schedule)) {
      for (const [period, type] of Object.entries(periods)) {
        insertPromises.push(
          pool.query(
            'INSERT INTO schedules (user_id, day, period, type) VALUES ($1, $2, $3, $4)',
            [req.user.id, day, parseInt(period), type]
          )
        );
      }
    }
    await Promise.all(insertPromises);

    res.json({ success: true });
  } catch (error) {
    console.error('Save account setup error:', error);
    res.status(500).json({ error: 'Failed to save account setup' });
  }
});

// ============ CALENDAR/TASK ROUTES ============

// Fetch Canvas calendar
app.post('/api/calendar/fetch', authenticateToken, async (req, res) => {
  try {
    const { canvasUrl } = req.body;

    if (!canvasUrl) {
      return res.status(400).json({ error: 'Canvas URL is required' });
    }

    const response = await axios.get(canvasUrl, {
      headers: {
        'Accept': 'text/calendar, text/plain, */*'
      },
      timeout: 10000
    });

    const icsData = response.data;

    if (!icsData.includes('BEGIN:VCALENDAR')) {
      return res.status(400).json({ 
        error: 'Invalid calendar format. Please check your Canvas calendar URL.' 
      });
    }

    const events = await ical.async.parseICS(icsData);
    const tasks = [];

    for (const event of Object.values(events)) {
      if (event.type === 'VEVENT' && event.summary) {
        tasks.push({
          title: event.summary,
          description: event.description || '',
          dueDate: event.start || event.end || new Date(),
        });
      }
    }

    await pool.query(
      'UPDATE users SET canvas_url = $1 WHERE id = $2',
      [canvasUrl, req.user.id]
    );

    res.json({ tasks });
  } catch (error) {
    console.error('Fetch calendar error:', error);
    if (error.code === 'ECONNABORTED') {
      res.status(408).json({ error: 'Request timeout. Please check your Canvas URL and try again.' });
    } else if (error.response?.status === 404) {
      res.status(404).json({ error: 'Canvas calendar not found. Please verify your URL is correct.' });
    } else {
      res.status(500).json({ error: 'Failed to fetch calendar. Please verify your Canvas URL is correct.' });
    }
  }
});

// Get tasks (including completed for display purposes)
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tasks WHERE user_id = $1 ORDER BY due_date ASC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(500).json({ error: 'Failed to get tasks' });
  }
});

// Save tasks (ENHANCED: preserves manual overrides)
app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { tasks } = req.body;

    // Get existing tasks with manual overrides
    const existingTasks = await pool.query(
      'SELECT title, user_estimate FROM tasks WHERE user_id = $1 AND user_estimate IS NOT NULL',
      [req.user.id]
    );

    // Create a map of manual overrides
    const overrideMap = {};
    existingTasks.rows.forEach(task => {
      overrideMap[task.title] = task.user_estimate;
    });

    // Clear existing incomplete tasks
    await pool.query('DELETE FROM tasks WHERE user_id = $1 AND completed = false', [req.user.id]);

    // Insert new tasks, preserving manual overrides
    const insertedTasks = [];
    for (const task of tasks) {
      const userEstimate = overrideMap[task.title] || task.userEstimate || null;
      
      const result = await pool.query(
        `INSERT INTO tasks (user_id, title, description, due_date, task_type, estimated_time, user_estimate, completed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, title, description, due_date, task_type, estimated_time, user_estimate, completed`,
        [
          req.user.id,
          task.title,
          task.description,
          task.dueDate,
          task.type,
          task.estimatedTime,
          userEstimate,
          task.completed || false
        ]
      );
      insertedTasks.push(result.rows[0]);
    }

    res.json({ success: true, tasks: insertedTasks });
  } catch (error) {
    console.error('Save tasks error:', error);
    res.status(500).json({ error: 'Failed to save tasks' });
  }
});

// Update task estimate
app.patch('/api/tasks/:id/estimate', authenticateToken, async (req, res) => {
  try {
    const { userEstimate } = req.body;
    const taskId = req.params.id;

    await pool.query(
      'UPDATE tasks SET user_estimate = $1 WHERE id = $2 AND user_id = $3',
      [userEstimate, taskId, req.user.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Update task estimate error:', error);
    res.status(500).json({ error: 'Failed to update estimate' });
  }
});

// Manual task completion (no time recorded)
app.patch('/api/tasks/:id/complete', authenticateToken, async (req, res) => {
  try {
    const taskId = req.params.id;

    await pool.query(
      'UPDATE tasks SET completed = true WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Complete task error:', error);
    res.status(500).json({ error: 'Failed to complete task' });
  }
});

// Get global estimate for a task title
app.get('/api/tasks/global-estimate/:title', authenticateToken, async (req, res) => {
  try {
    const taskTitle = decodeURIComponent(req.params.title);

    const result = await pool.query(
      `SELECT AVG(actual_time)::INTEGER as avg_time, COUNT(*) as completion_count
       FROM completion_history 
       WHERE task_title = $1
       GROUP BY task_title
       HAVING COUNT(*) >= 3`,
      [taskTitle]
    );

    if (result.rows.length > 0) {
      res.json({ 
        estimate: result.rows[0].avg_time,
        completionCount: result.rows[0].completion_count,
        source: 'global'
      });
    } else {
      res.json({ estimate: null });
    }
  } catch (error) {
    console.error('Get global estimate error:', error);
    res.status(500).json({ error: 'Failed to get global estimate' });
  }
});

// ============ SESSION ROUTES ============

// Get completion history (for AI learning)
app.get('/api/learning', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM completion_history WHERE user_id = $1 ORDER BY completed_at DESC LIMIT 100',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get learning error:', error);
    res.status(500).json({ error: 'Failed to get learning data' });
  }
});

// Save session completion
app.post('/api/sessions/complete', authenticateToken, async (req, res) => {
  try {
    const { completions, day, period } = req.body;

    const insertPromises = completions.map(completion =>
      pool.query(
        `INSERT INTO completion_history 
         (user_id, task_title, task_type, estimated_time, actual_time)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          req.user.id,
          completion.task.title,
          completion.task.type,
          completion.task.estimatedTime,
          completion.timeSpent
        ]
      )
    );

    await Promise.all(insertPromises);

    const taskIds = completions.map(c => c.task.id);
    if (taskIds.length > 0) {
      await pool.query(
        'UPDATE tasks SET completed = true WHERE id = ANY($1::int[]) AND user_id = $2',
        [taskIds, req.user.id]
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Save session error:', error);
    res.status(500).json({ error: 'Failed to save session' });
  }
});

// Save session state (for resume capability)
app.post('/api/sessions/save-state', authenticateToken, async (req, res) => {
  try {
    const { sessionId, day, period, remainingTime, currentTaskIndex, taskStartTime, completions } = req.body;

    // Delete any existing session state for this user
    await pool.query('DELETE FROM session_state WHERE user_id = $1', [req.user.id]);

    // Insert new session state
    await pool.query(
      `INSERT INTO session_state 
       (user_id, session_id, day, period, remaining_time, current_task_index, task_start_time, completions, saved_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)`,
      [req.user.id, sessionId, day, period, remainingTime, currentTaskIndex, taskStartTime, JSON.stringify(completions)]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Save session state error:', error);
    res.status(500).json({ error: 'Failed to save session state' });
  }
});

// Get saved session state
app.get('/api/sessions/saved-state', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM session_state WHERE user_id = $1',
      [req.user.id]
    );

    if (result.rows.length > 0) {
      const state = result.rows[0];
      res.json({
        sessionId: state.session_id,
        day: state.day,
        period: state.period,
        remainingTime: state.remaining_time,
        currentTaskIndex: state.current_task_index,
        taskStartTime: state.task_start_time,
        completions: JSON.parse(state.completions),
        savedAt: state.saved_at
      });
    } else {
      res.json({ savedState: null });
    }
  } catch (error) {
    console.error('Get session state error:', error);
    res.status(500).json({ error: 'Failed to get session state' });
  }
});

// Clear saved session state
app.delete('/api/sessions/saved-state', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM session_state WHERE user_id = $1', [req.user.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Clear session state error:', error);
    res.status(500).json({ error: 'Failed to clear session state' });
  }
});

// ============ HEALTH CHECK ============

app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'OneSchool Global Study Planner API' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
