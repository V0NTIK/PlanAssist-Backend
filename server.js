// OneSchool Global Study Planner - Backend API (TWO-ID SYSTEM)
// server.js - PART 1 of 2

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

// Initialize tables if they don't exist
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
    completed_task_ids INTEGER[] DEFAULT '{}',
    saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
  )
`).catch(err => console.error('Error creating session_state table:', err));

pool.query(`
  CREATE TABLE IF NOT EXISTS partial_completions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL,
    parent_task_id INTEGER NOT NULL,
    split_task_id INTEGER,
    task_title VARCHAR(500) NOT NULL,
    accumulated_time INTEGER NOT NULL DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, task_id)
  )
`).catch(err => console.error('Error creating partial_completions table:', err));

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

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

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
    console.error('Error details:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      error: 'Registration failed', 
      details: process.env.NODE_ENV === 'development' ? error.message : undefined 
    });
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
      grade: user.grade || '',
      canvasUrl: user.canvas_url || '',
      presentPeriods: user.present_periods || '2-6',
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

// Fetch Canvas calendar
app.post('/api/calendar/fetch', authenticateToken, async (req, res) => {
  try {
    const { canvasUrl } = req.body;
    
    // Accept both instructure.com and oneschoolglobal.com Canvas URLs
    const isValidCanvasUrl = canvasUrl && 
      (canvasUrl.includes('instructure.com/feeds/calendars') || 
       canvasUrl.includes('oneschoolglobal.com/feeds/calendars'));
    
    if (!isValidCanvasUrl) {
      return res.status(400).json({ 
        error: 'Invalid Canvas URL. Please use the format: https://canvas.oneschoolglobal.com/feeds/calendars/user_...' 
      });
    }

    let icsData;
    try {
      console.log('Fetching calendar from:', canvasUrl);
      const response = await axios.get(canvasUrl, { 
        timeout: 15000,
        headers: {
          'User-Agent': 'PlanAssist/1.0'
        }
      });
      console.log('Calendar fetch successful, response status:', response.status);
      icsData = response.data;
    } catch (error) {
      console.error('Error fetching calendar:', error.message);
      console.error('Error details:', {
        status: error.response?.status,
        statusText: error.response?.statusText,
        url: canvasUrl
      });
      return res.status(500).json({ 
        error: 'Failed to fetch calendar data. Please verify your Canvas URL is correct and accessible.',
        details: error.message 
      });
    }

    const events = await ical.async.parseICS(icsData);
    const tasks = [];
    
    // Calculate one month window from today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const oneMonthFromNow = new Date(today);
    oneMonthFromNow.setMonth(oneMonthFromNow.getMonth() + 1);

    for (const event of Object.values(events)) {
      if (event.type === 'VEVENT' && event.summary) {
        const eventDate = new Date(event.start || event.end || new Date());
        
        // Only include tasks within the next month
        if (eventDate >= today && eventDate <= oneMonthFromNow) {
          tasks.push({
            title: event.summary,
            description: event.description || '',
            dueDate: event.start || event.end || new Date(),
          });
        }
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
      'SELECT * FROM tasks WHERE user_id = $1 ORDER BY priority_order ASC NULLS LAST, due_date ASC',
      [req.user.id]
    );
    // Always return an array
    const rows = result.rows || [];
    res.json(rows);
  } catch (error) {
    console.error('Get tasks error:', error);
    // Return empty array on error instead of error object
    res.json([]);
  }
});

// Save tasks (TWO-ID SYSTEM - UPDATED)
app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { tasks } = req.body;

    // Validate that tasks is an array
    if (!Array.isArray(tasks)) {
      return res.status(400).json({ error: 'Tasks must be an array' });
    }

    // Get user's priority lock setting
    const userResult = await pool.query(
      'SELECT priority_locked FROM users WHERE id = $1',
      [req.user.id]
    );
    const priorityLocked = userResult.rows[0]?.priority_locked || false;

    // Get existing tasks with manual overrides and titles
    const existingTasks = await pool.query(
      'SELECT id, title, user_estimate, priority_order, parent_task_id, split_task_id FROM tasks WHERE user_id = $1',
      [req.user.id]
    );

    // Create a map of existing tasks by title
    const existingTaskMap = {};
    (existingTasks.rows || []).forEach(task => {
      existingTaskMap[task.title] = {
        userEstimate: task.user_estimate,
        priorityOrder: task.priority_order,
        parentTaskId: task.parent_task_id,
        splitTaskId: task.split_task_id
      };
    });

    // Identify new tasks
    const existingTitles = new Set(Object.keys(existingTaskMap));
    const incomingTitles = new Set(tasks.map(t => t.title));
    const newTaskTitles = new Set([...incomingTitles].filter(t => !existingTitles.has(t)));

    // Get max priority order for appending new tasks
    const maxPriorityResult = await pool.query(
      'SELECT MAX(priority_order) as max_priority FROM tasks WHERE user_id = $1',
      [req.user.id]
    );
    let nextPriority = (maxPriorityResult.rows[0]?.max_priority || 0) + 1;

    // Counter for generating unique split_task_ids PER PARENT (TWO-ID FIX)
    const splitCountersByParent = {};

    // Clear existing incomplete tasks
    await pool.query('DELETE FROM tasks WHERE user_id = $1 AND completed = false', [req.user.id]);

    // Insert new tasks, preserving manual overrides and priorities
    const insertedTasks = [];
    for (const task of tasks) {
      const userEstimate = existingTaskMap[task.title]?.userEstimate || task.userEstimate || null;
      const isNewTask = newTaskTitles.has(task.title);
      
      // Determine priority order
      let priorityOrder = null;
      if (existingTaskMap[task.title]?.priorityOrder !== undefined) {
        // Preserve existing priority
        priorityOrder = existingTaskMap[task.title].priorityOrder;
      } else if (!priorityLocked) {
        // Auto-assign priority if not locked (will sort by due_date via NULL)
        priorityOrder = null;
      } else if (isNewTask) {
        // New task with locked priorities - append to end
        priorityOrder = nextPriority++;
      }

      // Determine parent_task_id and split_task_id (TWO-ID SYSTEM - FIXED)
      let parentTaskId = task.parent_task_id || null;
      let splitTaskId = task.split_task_id || null;
      
      // If this is a split task with parent but no split ID yet, assign one
      if (parentTaskId && !splitTaskId) {
        // Initialize counter for this parent if not exists
        if (!splitCountersByParent[parentTaskId]) {
          splitCountersByParent[parentTaskId] = 0;
        }
        // Assign next split ID for this parent
        splitTaskId = ++splitCountersByParent[parentTaskId];
      }
      
      const result = await pool.query(
        `INSERT INTO tasks (user_id, parent_task_id, split_task_id, title, description, due_date, task_type, estimated_time, user_estimate, priority_order, is_new, completed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING *`,
        [
          req.user.id,
          parentTaskId,
          splitTaskId,
          task.title,
          task.description,
          task.dueDate,
          task.type,
          task.estimatedTime,
          userEstimate,
          priorityOrder,
          priorityLocked && isNewTask, // Mark as new only if priority is locked
          task.completed || false
        ]
      );
      
      const insertedTask = result.rows[0];
      
      // CRITICAL FIX: If this is a new base task (no parent set), set parent_task_id = id
      if (!parentTaskId) {
        await pool.query(
          'UPDATE tasks SET parent_task_id = id WHERE id = $1',
          [insertedTask.id]
        );
        insertedTask.parent_task_id = insertedTask.id;
      }
      
      insertedTasks.push(insertedTask);
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

// Reorder tasks (update priority_order for all tasks)
app.post('/api/tasks/reorder', authenticateToken, async (req, res) => {
  try {
    const { taskOrder } = req.body; // Array of task IDs in desired order

    if (!Array.isArray(taskOrder)) {
      return res.status(400).json({ error: 'taskOrder must be an array' });
    }

    // Update priority_order for each task
    const updatePromises = taskOrder.map((taskId, index) =>
      pool.query(
        'UPDATE tasks SET priority_order = $1 WHERE id = $2 AND user_id = $3',
        [index + 1, taskId, req.user.id]
      )
    );

    await Promise.all(updatePromises);

    res.json({ success: true });
  } catch (error) {
    console.error('Reorder tasks error:', error);
    res.status(500).json({ error: 'Failed to reorder tasks' });
  }
});

// Toggle priority lock
app.patch('/api/user/priority-lock', authenticateToken, async (req, res) => {
  try {
    const { locked } = req.body;

    await pool.query(
      'UPDATE users SET priority_locked = $1 WHERE id = $2',
      [locked, req.user.id]
    );

    // If unlocking, clear all priority orders and new flags
    if (!locked) {
      await pool.query(
        'UPDATE tasks SET priority_order = NULL, is_new = FALSE WHERE user_id = $1',
        [req.user.id]
      );
    }

    res.json({ success: true, locked });
  } catch (error) {
    console.error('Toggle priority lock error:', error);
    res.status(500).json({ error: 'Failed to toggle priority lock' });
  }
});

// Get priority lock status
app.get('/api/user/priority-lock', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT priority_locked FROM users WHERE id = $1',
      [req.user.id]
    );

    const locked = result.rows[0]?.priority_locked || false;
    res.json({ locked });
  } catch (error) {
    console.error('Get priority lock error:', error);
    res.status(500).json({ error: 'Failed to get priority lock status' });
  }
});

// Clear new task flags (move from sidebar to main list)
app.post('/api/tasks/clear-new-flags', authenticateToken, async (req, res) => {
  try {
    const { taskIds } = req.body;

    if (!Array.isArray(taskIds)) {
      return res.status(400).json({ error: 'taskIds must be an array' });
    }

    if (taskIds.length === 0) {
      return res.json({ success: true });
    }

    await pool.query(
      'UPDATE tasks SET is_new = FALSE WHERE id = ANY($1::int[]) AND user_id = $2',
      [taskIds, req.user.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Clear new flags error:', error);
    res.status(500).json({ error: 'Failed to clear new flags' });
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

// Get partial completions
app.get('/api/tasks/partial-completions', authenticateToken, async (req, res) => {
  try {
    // Get all partial completions with parent_task_id
    const result = await pool.query(
      `SELECT 
         parent_task_id,
         task_id,
         split_task_id,
         task_title,
         accumulated_time,
         last_updated
       FROM partial_completions 
       WHERE user_id = $1
       ORDER BY parent_task_id, split_task_id`,
      [req.user.id]
    );

    res.json({ partialCompletions: result.rows });
  } catch (error) {
    console.error('Get partial completions error:', error);
    res.status(500).json({ error: 'Failed to get partial completions' });
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
    // Always return an array, even if empty
    const rows = result.rows || [];
    res.json(rows);
  } catch (error) {
    console.error('Get learning error:', error);
    // Return empty array on error instead of error object
    res.json([]);
  }
});

// END OF PART 1
// Continue to server_part2.js

// OneSchool Global Study Planner - Backend API (TWO-ID SYSTEM)
// server.js - PART 2 of 2
// This continues from server_part1.js

// Immediate task completion (TWO-ID SYSTEM - UPDATED)
app.post('/api/sessions/complete-task', authenticateToken, async (req, res) => {
  try {
    const { taskId, taskTitle, taskType, estimatedTime, actualTime } = req.body;

    console.log(`\n=== COMPLETING TASK ${taskId} ===`);

    // Get the task details including parent_task_id and split_task_id
    const taskResult = await pool.query(
      'SELECT title, task_type, estimated_time, parent_task_id, split_task_id FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    if (taskResult.rows.length === 0) {
      console.log('Task not found');
      return res.status(404).json({ error: 'Task not found' });
    }

    const task = taskResult.rows[0];
    const parentTaskId = task.parent_task_id || taskId; // If no parent, this IS the parent
    const splitTaskId = task.split_task_id;
    const isSegment = task.parent_task_id !== null;

    console.log('Task:', task.title);
    console.log('Parent ID:', parentTaskId, '| Split ID:', splitTaskId, '| Is Segment:', isSegment);

    // Get any accumulated partial time for this specific task
    const partialResult = await pool.query(
      'SELECT accumulated_time FROM partial_completions WHERE user_id = $1 AND task_id = $2',
      [req.user.id, taskId]
    );

    const partialTime = partialResult.rows.length > 0 ? partialResult.rows[0].accumulated_time : 0;
    const totalTime = actualTime + partialTime;

    console.log('Time - Session:', actualTime, '| Partial:', partialTime, '| Total:', totalTime);

    // Mark task as completed
    await pool.query(
      'UPDATE tasks SET completed = true WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    // Remove this task's partial completion
    await pool.query(
      'DELETE FROM partial_completions WHERE user_id = $1 AND task_id = $2',
      [req.user.id, taskId]
    );

    // Insert individual completion record
    await pool.query(
      `INSERT INTO completion_history 
       (user_id, task_id, parent_task_id, task_title, task_type, estimated_time, actual_time, is_segment)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        req.user.id,
        taskId,
        parentTaskId,
        task.title,
        task.task_type,
        task.estimated_time,
        totalTime,
        isSegment
      ]
    );

    console.log('✓ Individual completion recorded');

    // If this is a segment, check if ALL segments of the parent are now complete
    if (isSegment) {
      console.log('Checking if all segments of parent', parentTaskId, 'are complete...');

      // Get all segments of this parent task
      const allSegmentsResult = await pool.query(
        'SELECT id, completed, estimated_time FROM tasks WHERE user_id = $1 AND parent_task_id = $2',
        [req.user.id, parentTaskId]
      );

      const allSegments = allSegmentsResult.rows;
      const allComplete = allSegments.every(seg => seg.completed);

      console.log(`Found ${allSegments.length} segments, ${allComplete ? 'ALL' : 'NOT ALL'} complete`);

      if (allComplete && allSegments.length > 0) {
        console.log('🎉 All segments complete! Creating consolidated completion record...');

        // Get all individual segment completions for this parent
        const segmentCompletionsResult = await pool.query(
          `SELECT task_title, task_type, estimated_time, actual_time 
           FROM completion_history 
           WHERE user_id = $1 AND parent_task_id = $2 AND is_segment = true`,
          [req.user.id, parentTaskId]
        );

        const segmentCompletions = segmentCompletionsResult.rows;
        
        // Calculate totals
        const totalEstimatedTime = segmentCompletions.reduce((sum, seg) => sum + seg.estimated_time, 0);
        const totalActualTime = segmentCompletions.reduce((sum, seg) => sum + seg.actual_time, 0);
        
        // Get the parent task title (remove segment suffix from first segment)
        const firstSegmentTitle = segmentCompletions[0].task_title;
        const parentTitle = firstSegmentTitle
          .replace(/ - Part \d+$/, '')
          .replace(/ - Segment \d+$/, '')
          .trim();

        console.log('Consolidated stats:');
        console.log('  Title:', parentTitle);
        console.log('  Estimated:', totalEstimatedTime, '| Actual:', totalActualTime);

        // Check if consolidated record already exists (shouldn't, but just in case)
        const existingConsolidated = await pool.query(
          `SELECT id FROM completion_history 
           WHERE user_id = $1 AND parent_task_id = $2 AND is_segment = false`,
          [req.user.id, parentTaskId]
        );

        if (existingConsolidated.rows.length === 0) {
          // Insert consolidated completion record
          await pool.query(
            `INSERT INTO completion_history 
             (user_id, task_id, parent_task_id, task_title, task_type, estimated_time, actual_time, is_segment)
             VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
            [
              req.user.id,
              parentTaskId,
              parentTaskId,
              parentTitle,
              segmentCompletions[0].task_type,
              totalEstimatedTime,
              totalActualTime
            ]
          );

          // CRITICAL FIX: Delete individual segment records now that we have consolidated
          await pool.query(
            `DELETE FROM completion_history 
             WHERE user_id = $1 AND parent_task_id = $2 AND is_segment = true`,
            [req.user.id, parentTaskId]
          );

          console.log('✓ Consolidated completion record created and segment records removed!');
        } else {
          console.log('ℹ Consolidated record already exists');
        }
      }
    }

    console.log('=== COMPLETION DONE ===\n');
    res.json({ success: true });
  } catch (error) {
    console.error('Complete task error:', error);
    res.status(500).json({ error: 'Failed to complete task' });
  }
});

// Save session completion (batch completion at end of session) (TWO-ID SYSTEM - UPDATED)
app.post('/api/sessions/complete', authenticateToken, async (req, res) => {
  try {
    const { completions } = req.body;

    console.log('\n=== BATCH COMPLETING', completions.length, 'TASKS ===');

    // Track which parent tasks we've processed
    const processedParents = new Set();

    // Process each completion
    for (const completion of completions) {
      const taskId = completion.task.id;
      const taskTitle = completion.task.title;
      const taskType = completion.task.type;
      const estimatedTime = completion.task.estimatedTime;
      const actualTime = completion.timeSpent;

      // Get task details including parent_task_id and split_task_id
      const taskResult = await pool.query(
        'SELECT parent_task_id, split_task_id FROM tasks WHERE id = $1 AND user_id = $2',
        [taskId, req.user.id]
      );

      const parentTaskId = taskResult.rows.length > 0 
        ? (taskResult.rows[0].parent_task_id || taskId)
        : taskId;
      const splitTaskId = taskResult.rows.length > 0 
        ? taskResult.rows[0].split_task_id 
        : null;
      const isSegment = taskResult.rows.length > 0 && taskResult.rows[0].parent_task_id !== null;

      // Get any partial time
      const partialResult = await pool.query(
        'SELECT accumulated_time FROM partial_completions WHERE user_id = $1 AND task_id = $2',
        [req.user.id, taskId]
      );

      const partialTime = partialResult.rows.length > 0 ? partialResult.rows[0].accumulated_time : 0;
      const totalTime = actualTime + partialTime;

      // Insert individual completion
      await pool.query(
        `INSERT INTO completion_history 
         (user_id, task_id, parent_task_id, task_title, task_type, estimated_time, actual_time, is_segment)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [req.user.id, taskId, parentTaskId, taskTitle, taskType, estimatedTime, totalTime, isSegment]
      );

      // Mark task as completed
      await pool.query(
        'UPDATE tasks SET completed = true WHERE id = $1 AND user_id = $2',
        [taskId, req.user.id]
      );

      // Remove from partial completions
      await pool.query(
        'DELETE FROM partial_completions WHERE user_id = $1 AND task_id = $2',
        [req.user.id, taskId]
      );

      console.log('✓ Completed:', taskTitle.substring(0, 50), `(${totalTime} min)`);

      // Check if we need to create consolidated record for this parent
      if (isSegment && !processedParents.has(parentTaskId)) {
        // Get all segments of this parent
        const allSegmentsResult = await pool.query(
          'SELECT id, completed FROM tasks WHERE user_id = $1 AND parent_task_id = $2',
          [req.user.id, parentTaskId]
        );

        const allComplete = allSegmentsResult.rows.every(seg => seg.completed);

        if (allComplete && allSegmentsResult.rows.length > 0) {
          // Get all segment completions
          const segmentCompletionsResult = await pool.query(
            `SELECT task_title, task_type, estimated_time, actual_time 
             FROM completion_history 
             WHERE user_id = $1 AND parent_task_id = $2 AND is_segment = true`,
            [req.user.id, parentTaskId]
          );

          const segments = segmentCompletionsResult.rows;
          const totalEst = segments.reduce((sum, s) => sum + s.estimated_time, 0);
          const totalAct = segments.reduce((sum, s) => sum + s.actual_time, 0);
          
          const parentTitle = segments[0].task_title
            .replace(/ - Part \d+$/, '')
            .replace(/ - Segment \d+$/, '')
            .trim();

          // Insert consolidated record
          await pool.query(
            `INSERT INTO completion_history 
             (user_id, task_id, parent_task_id, task_title, task_type, estimated_time, actual_time, is_segment)
             VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
            [req.user.id, parentTaskId, parentTaskId, parentTitle, segments[0].task_type, totalEst, totalAct]
          );

          // CRITICAL FIX: Delete individual segment records now that we have consolidated
          await pool.query(
            `DELETE FROM completion_history 
             WHERE user_id = $1 AND parent_task_id = $2 AND is_segment = true`,
            [req.user.id, parentTaskId]
          );

          console.log('  🎉 Consolidated', segments.length, 'segments into one record and removed segment entries');
          processedParents.add(parentTaskId);
        }
      }
    }

    console.log('=== BATCH COMPLETE DONE ===\n');
    res.json({ success: true });
  } catch (error) {
    console.error('Session complete error:', error);
    res.status(500).json({ error: 'Failed to complete session' });
  }
});

// Save session state (for resume capability) (TWO-ID SYSTEM - UPDATED)
app.post('/api/sessions/save-state', authenticateToken, async (req, res) => {
  try {
    const { sessionId, day, period, remainingTime, currentTaskIndex, taskStartTime, completedTaskIds, partialTaskId, partialTaskTime, partialTaskTitle } = req.body;

    console.log('=== SAVE STATE REQUEST ===');
    console.log('Session ID:', sessionId);
    console.log('Partial Task ID:', partialTaskId);
    console.log('Partial Task Title:', partialTaskTitle);
    console.log('Partial Task Time:', partialTaskTime);
    console.log('Completed Task IDs:', completedTaskIds);

    // Delete any existing session state for this user
    await pool.query('DELETE FROM session_state WHERE user_id = $1', [req.user.id]);

    // If there's a partial task with time spent, save or update its partial completion time
    if (partialTaskId && partialTaskTime && partialTaskTime > 0) {
      console.log('Attempting to save partial completion for task ID:', partialTaskId);
      
      // Get the task from database including parent_task_id and split_task_id
      const taskResult = await pool.query(
        'SELECT title, completed, parent_task_id, split_task_id FROM tasks WHERE id = $1 AND user_id = $2',
        [partialTaskId, req.user.id]
      );

      let taskTitle = partialTaskTitle || 'Unknown Task';
      let parentTaskId = partialTaskId; // Default to current task ID
      let splitTaskId = null;
      let shouldSave = true;

      if (taskResult.rows.length > 0) {
        const task = taskResult.rows[0];
        taskTitle = task.title;
        
        // Determine parent_task_id: use task's parent_task_id if it exists, otherwise use task's own ID
        parentTaskId = task.parent_task_id || partialTaskId;
        splitTaskId = task.split_task_id;
        
        if (task.completed) {
          console.log('⚠ Task is already marked as completed, skipping save');
          shouldSave = false;
        } else {
          console.log('✓ Found task:', taskTitle);
          console.log('  Parent ID:', parentTaskId, '| Split ID:', splitTaskId);
        }
      } else {
        console.log('⚠ Task not found in database, using provided title:', taskTitle);
      }

      if (shouldSave) {
        // Check if partial completion already exists for THIS SPECIFIC TASK
        const existingPartial = await pool.query(
          'SELECT accumulated_time FROM partial_completions WHERE user_id = $1 AND task_id = $2',
          [req.user.id, partialTaskId]
        );

        if (existingPartial.rows.length > 0) {
          // Update existing partial completion
          const result = await pool.query(
            `UPDATE partial_completions 
             SET accumulated_time = accumulated_time + $1,
                 task_title = $2,
                 parent_task_id = $3,
                 split_task_id = $4,
                 last_updated = CURRENT_TIMESTAMP
             WHERE user_id = $5 AND task_id = $6
             RETURNING accumulated_time`,
            [partialTaskTime, taskTitle, parentTaskId, splitTaskId, req.user.id, partialTaskId]
          );
          
          console.log('✓ Updated partial completion. Accumulated:', result.rows[0].accumulated_time, 'min');
        } else {
          // Insert new partial completion
          const result = await pool.query(
            `INSERT INTO partial_completions 
             (user_id, task_id, parent_task_id, split_task_id, task_title, accumulated_time, last_updated)
             VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
             RETURNING accumulated_time`,
            [req.user.id, partialTaskId, parentTaskId, splitTaskId, taskTitle, partialTaskTime]
          );
          
          console.log('✓ Created partial completion:', result.rows[0].accumulated_time, 'min');
        }
      }
    } else {
      console.log('ℹ No partial task to save (partialTaskId:', partialTaskId, ', time:', partialTaskTime, ')');
    }

    // Insert new session state
    await pool.query(
      `INSERT INTO session_state 
       (user_id, session_id, day, period, remaining_time, current_task_index, task_start_time, completed_task_ids, saved_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)`,
      [req.user.id, sessionId, day, period, remainingTime, currentTaskIndex, taskStartTime, completedTaskIds || []]
    );

    console.log('✓ Session state saved successfully');
    console.log('=========================\n');
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Save session state error:', error);
    console.error('Error details:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to save session state', details: error.message });
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

      // Get all partial completions for this user (grouped by parent_task_id)
      const partialResult = await pool.query(
        'SELECT task_id, parent_task_id, accumulated_time FROM partial_completions WHERE user_id = $1',
        [req.user.id]
      );

      // Group by parent_task_id for display
      const partialTaskTimes = {};
      partialResult.rows.forEach(row => {
        const parentId = row.parent_task_id;
        if (partialTaskTimes[parentId]) {
          partialTaskTimes[parentId] += row.accumulated_time;
        } else {
          partialTaskTimes[parentId] = row.accumulated_time;
        }
      });
      
      res.json({
        sessionId: state.session_id,
        day: state.day,
        period: state.period,
        remainingTime: state.remaining_time,
        currentTaskIndex: state.current_task_index,
        taskStartTime: state.task_start_time,
        completedTaskIds: state.completed_task_ids || [],
        partialTaskTimes: partialTaskTimes,
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

// ============ FEEDBACK ROUTE ============

app.post('/api/feedback', authenticateToken, async (req, res) => {
  try {
    const { feedback, userEmail, userName } = req.body;

    if (!feedback || feedback.trim().length === 0) {
      return res.status(400).json({ error: 'Feedback cannot be empty' });
    }

    await pool.query(
      'INSERT INTO feedback (user_id, user_email, user_name, feedback_text, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)',
      [req.user.id, userEmail, userName, feedback]
    );

    res.json({ success: true, message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).json({ error: 'Failed to submit feedback' });
  }
});

// ============ HEALTH CHECK ============

app.get('/health', async (req, res) => {
  try {
    // Test database connection
    await pool.query('SELECT 1');
    res.json({ 
      status: 'ok', 
      message: 'OneSchool Global Study Planner API (TWO-ID SYSTEM)',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Database connection failed',
      error: error.message 
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('TWO-ID SYSTEM ACTIVE');
});

// END OF PART 2
