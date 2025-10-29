// OneSchool Global Study Planner - Backend API (TWO-ID SYSTEM + ID PRESERVATION FIX)
// server.js - COMPLETE FILE WITH FIXED /api/tasks ENDPOINT

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

    for (const day in schedule) {
      for (const period in schedule[day]) {
        await pool.query(
          'INSERT INTO schedules (user_id, day, period, type) VALUES ($1, $2, $3, $4)',
          [req.user.id, day, parseInt(period), schedule[day][period]]
        );
      }
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Save account setup error:', error);
    res.status(500).json({ error: 'Failed to save account setup' });
  }
});

// ============ CANVAS INTEGRATION ============

app.post('/api/canvas/fetch', authenticateToken, async (req, res) => {
  try {
    const { canvasUrl } = req.body;
    
    if (!canvasUrl) {
      return res.status(400).json({ error: 'Canvas URL is required' });
    }

    const response = await axios.get(canvasUrl, {
      timeout: 10000,
      headers: {
        'User-Agent': 'PlanAssist/1.0'
      }
    });

    const events = ical.sync.parseICS(response.data);
    const tasks = [];

    for (const event of Object.values(events)) {
      if (event.type === 'VEVENT') {
        const title = event.summary || 'Untitled';
        const description = event.description || '';
        const dueDate = event.end || event.start;
        
        let type = 'other';
        const lowerTitle = title.toLowerCase();
        if (lowerTitle.includes('quiz') || lowerTitle.includes('test')) {
          type = 'quiz';
        } else if (lowerTitle.includes('assignment') || lowerTitle.includes('homework')) {
          type = 'assignment';
        }

        if (dueDate) {
          tasks.push({
            title,
            description,
            dueDate: dueDate.toISOString(),
            type,
            estimatedTime: type === 'quiz' ? 30 : 60,
            completed: false
          });
        }
      }
    }

    res.json({ tasks });
  } catch (error) {
    console.error('Canvas fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch Canvas tasks',
      details: error.message 
    });
  }
});

// ============ TASK ROUTES ============

// Get all tasks
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tasks WHERE user_id = $1 ORDER BY priority_order NULLS FIRST, due_date ASC',
      [req.user.id]
    );

    const tasks = result.rows.map(task => ({
      id: task.id,
      title: task.title,
      description: task.description,
      dueDate: task.due_date,
      type: task.task_type,
      estimatedTime: task.estimated_time,
      userEstimate: task.user_estimate,
      completed: task.completed,
      completedAt: task.completed_at,
      priorityOrder: task.priority_order,
      isNew: task.is_new,
      parent_task_id: task.parent_task_id,
      split_task_id: task.split_task_id
    }));

    res.json(tasks);
  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(500).json({ error: 'Failed to get tasks' });
  }
});

// ============ FIXED: SAVE TASKS (UPDATE INSTEAD OF DELETE+INSERT) ============
app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { tasks } = req.body;

    // Validate that tasks is an array
    if (!Array.isArray(tasks)) {
      return res.status(400).json({ error: 'Tasks must be an array' });
    }

    console.log('=== SAVE TASKS (ID PRESERVATION) ===');
    console.log('Incoming tasks:', tasks.length);

    // Get priority lock status
    const userResult = await pool.query(
      'SELECT priority_locked FROM users WHERE id = $1',
      [req.user.id]
    );
    const priorityLocked = userResult.rows[0]?.priority_locked || false;

    // Get existing incomplete tasks (for preserving user estimates and priority)
    const existingResult = await pool.query(
      'SELECT id, title, user_estimate, priority_order FROM tasks WHERE user_id = $1 AND completed = false',
      [req.user.id]
    );
    
    const existingTaskMap = {};
    existingResult.rows.forEach(t => {
      existingTaskMap[t.title] = {
        id: t.id,
        userEstimate: t.user_estimate,
        priorityOrder: t.priority_order
      };
    });

    // Identify new tasks (not in existing map)
    const newTaskTitles = new Set();
    tasks.forEach(task => {
      if (!existingTaskMap[task.title]) {
        newTaskTitles.add(task.title);
      }
    });

    // Get max priority for new tasks
    const maxPriorityResult = await pool.query(
      'SELECT MAX(priority_order) as max_priority FROM tasks WHERE user_id = $1',
      [req.user.id]
    );
    let nextPriority = (maxPriorityResult.rows[0]?.max_priority || 0) + 1;

    // Get ALL existing incomplete tasks with their full details for matching
    const allExistingResult = await pool.query(
      'SELECT id, title, parent_task_id, split_task_id FROM tasks WHERE user_id = $1 AND completed = false',
      [req.user.id]
    );
    
    // Create mapping: "title|parent|split" -> task
    const existingTasksByKey = {};
    allExistingResult.rows.forEach(t => {
      const key = `${t.title}|${t.parent_task_id || 'null'}|${t.split_task_id || 'null'}`;
      existingTasksByKey[key] = t;
    });

    console.log('Existing tasks by key:', Object.keys(existingTasksByKey).length);

    // Track which existing IDs we update (to delete the rest)
    const updatedIds = new Set();
    
    // Track split_task_id counters per parent
    const splitCountersByParent = {};

    // Process all tasks
    const processedTasks = [];
    
    for (const task of tasks) {
      const userEstimate = existingTaskMap[task.title]?.userEstimate || task.userEstimate || null;
      const isNewTask = newTaskTitles.has(task.title);
      
      // Determine priority order
      let priorityOrder = null;
      if (existingTaskMap[task.title]?.priorityOrder !== undefined) {
        priorityOrder = existingTaskMap[task.title].priorityOrder;
      } else if (!priorityLocked) {
        priorityOrder = null;
      } else if (isNewTask) {
        priorityOrder = nextPriority++;
      }

      // Determine parent_task_id and split_task_id
      let parentTaskId = task.parent_task_id || null;
      let splitTaskId = task.split_task_id || null;
      
      // Assign split ID if needed
      if (parentTaskId && !splitTaskId) {
        if (!splitCountersByParent[parentTaskId]) {
          splitCountersByParent[parentTaskId] = 0;
        }
        splitTaskId = ++splitCountersByParent[parentTaskId];
      }
      
      // Create matching key
      const taskKey = `${task.title}|${parentTaskId || 'null'}|${splitTaskId || 'null'}`;
      const existingTask = existingTasksByKey[taskKey];
      
      if (existingTask) {
        // UPDATE existing task (preserves ID and partial completions)
        console.log(`✓ Updating task ID ${existingTask.id}: ${task.title.substring(0, 30)}...`);
        
        const result = await pool.query(
          `UPDATE tasks 
           SET description = $1,
               due_date = $2,
               task_type = $3,
               estimated_time = $4,
               user_estimate = $5,
               priority_order = $6,
               is_new = $7,
               parent_task_id = $8,
               split_task_id = $9
           WHERE id = $10 AND user_id = $11
           RETURNING *`,
          [
            task.description,
            task.dueDate,
            task.type,
            task.estimatedTime,
            userEstimate,
            priorityOrder,
            priorityLocked && isNewTask,
            parentTaskId || existingTask.id, // Set to self if null
            splitTaskId,
            existingTask.id,
            req.user.id
          ]
        );
        
        const updatedTask = result.rows[0];
        
        // Ensure parent_task_id is set for base tasks
        if (!parentTaskId) {
          await pool.query('UPDATE tasks SET parent_task_id = id WHERE id = $1', [updatedTask.id]);
          updatedTask.parent_task_id = updatedTask.id;
        }
        
        processedTasks.push(updatedTask);
        updatedIds.add(existingTask.id);
        
      } else {
        // INSERT new task
        console.log(`+ Inserting new task: ${task.title.substring(0, 30)}...`);
        
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
            priorityLocked && isNewTask,
            task.completed || false
          ]
        );
        
        const insertedTask = result.rows[0];
        
        // Set parent_task_id = id for base tasks
        if (!parentTaskId) {
          await pool.query('UPDATE tasks SET parent_task_id = id WHERE id = $1', [insertedTask.id]);
          insertedTask.parent_task_id = insertedTask.id;
        }
        
        processedTasks.push(insertedTask);
        updatedIds.add(insertedTask.id);
      }
    }
    
    // Delete tasks that were removed
    const allExistingIds = allExistingResult.rows.map(t => t.id);
    const idsToDelete = allExistingIds.filter(id => !updatedIds.has(id));
    
    if (idsToDelete.length > 0) {
      await pool.query(
        'DELETE FROM tasks WHERE id = ANY($1::int[]) AND user_id = $2',
        [idsToDelete, req.user.id]
      );
      console.log('- Deleted', idsToDelete.length, 'removed tasks:', idsToDelete);
    }

    console.log('Updated/kept:', updatedIds.size, 'tasks');
    console.log('=== SAVE COMPLETE ===\n');

    res.json({ success: true, tasks: processedTasks });
  } catch (error) {
    console.error('Save tasks error:', error);
    console.error('Error details:', error.message);
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
    const { taskIds } = req.body;

    for (let i = 0; i < taskIds.length; i++) {
      await pool.query(
        'UPDATE tasks SET priority_order = $1 WHERE id = $2 AND user_id = $3',
        [i + 1, taskIds[i], req.user.id]
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Reorder tasks error:', error);
    res.status(500).json({ error: 'Failed to reorder tasks' });
  }
});

// Toggle priority lock
app.post('/api/tasks/priority-lock', authenticateToken, async (req, res) => {
  try {
    const { locked } = req.body;

    await pool.query(
      'UPDATE users SET priority_locked = $1 WHERE id = $2',
      [locked, req.user.id]
    );

    if (locked) {
      const tasks = await pool.query(
        'SELECT id FROM tasks WHERE user_id = $1 AND completed = false AND priority_order IS NULL ORDER BY due_date ASC, id ASC',
        [req.user.id]
      );

      for (let i = 0; i < tasks.rows.length; i++) {
        await pool.query(
          'UPDATE tasks SET priority_order = $1 WHERE id = $2',
          [i + 1, tasks.rows[i].id]
        );
      }
    } else {
      await pool.query(
        'UPDATE tasks SET priority_order = NULL WHERE user_id = $1',
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
app.get('/api/tasks/priority-lock', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT priority_locked FROM users WHERE id = $1',
      [req.user.id]
    );

    res.json({ locked: result.rows[0]?.priority_locked || false });
  } catch (error) {
    console.error('Get priority lock error:', error);
    res.status(500).json({ error: 'Failed to get priority lock status' });
  }
});

// Clear new task flags
app.post('/api/tasks/clear-new', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'UPDATE tasks SET is_new = false WHERE user_id = $1 AND is_new = true',
      [req.user.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Clear new flags error:', error);
    res.status(500).json({ error: 'Failed to clear new task flags' });
  }
});

// ============ SESSION ROUTES ============

// Get all sessions
app.get('/api/sessions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM sessions WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({ error: 'Failed to get sessions' });
  }
});

// Create session
app.post('/api/sessions', authenticateToken, async (req, res) => {
  try {
    const { sessionId, day, period, startTime, plannedTasks } = req.body;

    const result = await pool.query(
      `INSERT INTO sessions (user_id, session_id, day, period, start_time, planned_tasks)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [req.user.id, sessionId, day, period, startTime, JSON.stringify(plannedTasks)]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Create session error:', error);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

// Complete session
app.post('/api/sessions/complete', authenticateToken, async (req, res) => {
  try {
    const { sessionId, completedTasks, totalTime, completionsSummary } = req.body;

    console.log('=== BATCH COMPLETE START ===');
    console.log('Session ID:', sessionId);
    console.log('Total completions:', completedTasks.length);
    console.log('Completions summary:', completionsSummary);

    await pool.query(
      `UPDATE sessions 
       SET completed = true, 
           end_time = CURRENT_TIMESTAMP,
           actual_time = $1,
           completed_tasks = $2
       WHERE session_id = $3 AND user_id = $4`,
      [totalTime, JSON.stringify(completedTasks), sessionId, req.user.id]
    );

    const processedParents = new Set();

    for (const task of completedTasks) {
      console.log('\n--- Processing task:', task.title);
      console.log('  Task ID:', task.id);
      console.log('  Parent ID:', task.parent_task_id);
      console.log('  Split ID:', task.split_task_id);
      console.log('  Time spent:', task.timeSpent, 'min');

      const result = await pool.query(
        `INSERT INTO completions (user_id, task_id, session_id, time_spent, completed_at)
         VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
         RETURNING *`,
        [req.user.id, task.id, sessionId, task.timeSpent]
      );

      await pool.query(
        'UPDATE tasks SET completed = true, completed_at = CURRENT_TIMESTAMP WHERE id = $1',
        [task.id]
      );

      console.log('  âœ" Marked complete, logged completion');

      const parentTaskId = task.parent_task_id;

      if (parentTaskId && !processedParents.has(parentTaskId)) {
        const segments = await pool.query(
          `SELECT id, split_task_id, completed 
           FROM tasks 
           WHERE user_id = $1 AND parent_task_id = $2 AND split_task_id IS NOT NULL
           ORDER BY split_task_id`,
          [req.user.id, parentTaskId]
        );

        console.log('  Found', segments.rows.length, 'total segments for parent', parentTaskId);

        const allComplete = segments.rows.every(seg => seg.completed);
        console.log('  All segments complete?', allComplete);

        if (allComplete) {
          await pool.query(
            `DELETE FROM partial_completions 
             WHERE user_id = $1 AND parent_task_id = $2`,
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
          // Update existing partial completion (trigger will update last_updated)
          const result = await pool.query(
            `UPDATE partial_completions 
             SET accumulated_time = accumulated_time + $1,
                 task_title = $2,
                 parent_task_id = $3,
                 split_task_id = $4
             WHERE user_id = $5 AND task_id = $6
             RETURNING accumulated_time`,
            [partialTaskTime, taskTitle, parentTaskId, splitTaskId, req.user.id, partialTaskId]
          );
          
          console.log('✓ Updated partial completion. Accumulated:', result.rows[0].accumulated_time, 'min');
        } else {
          // Insert new partial completion (last_updated defaults to CURRENT_TIMESTAMP)
          const result = await pool.query(
            `INSERT INTO partial_completions 
             (user_id, task_id, parent_task_id, split_task_id, task_title, accumulated_time)
             VALUES ($1, $2, $3, $4, $5, $6)
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
      message: 'OneSchool Global Study Planner API (TWO-ID + ID PRESERVATION)',
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
  console.log('TWO-ID SYSTEM + ID PRESERVATION ACTIVE');
});
