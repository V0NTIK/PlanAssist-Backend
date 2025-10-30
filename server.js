// PlanAssist - COMPLETELY REDESIGNED Backend API
// server.js - New title/segment system with advanced AI estimation
// FIXED: Added column aliasing for frontend compatibility

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

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Extract name from email
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

// Extract title from Canvas SUMMARY (removes class in brackets)
const extractTitle = (summary) => {
  // Remove everything from the last opening bracket onwards
  const lastBracketIndex = summary.lastIndexOf('[');
  if (lastBracketIndex > 0) {
    return summary.substring(0, lastBracketIndex).trim();
  }
  return summary.trim();
};

// Extract class from Canvas SUMMARY (last bracketed phrase)
const extractClass = (summary) => {
  const match = summary.match(/\[([^\]]+)\]$/);
  return match ? `[${match[1]}]` : '[Unknown Class]';
};

// Convert Canvas calendar URL to assignment URL
const convertToAssignmentUrl = (calendarUrl) => {
  // Input format: https://canvas.oneschoolglobal.com/calendar?include_contexts=course_[NUM1]&month=10&year=2025#assignment_[NUM2]
  // Output format: https://canvas.oneschoolglobal.com/courses/[NUM1]/assignments/[NUM2]
  
  // Handle undefined, null, or non-string values
  if (!calendarUrl || typeof calendarUrl !== 'string') {
    console.log('⚠️  Invalid calendar URL:', calendarUrl);
    return '';
  }
  
  try {
    const courseMatch = calendarUrl.match(/course_(\d+)/);
    const assignmentMatch = calendarUrl.match(/assignment_(\d+)/);
    
    if (courseMatch && assignmentMatch) {
      const courseId = courseMatch[1];
      const assignmentId = assignmentMatch[1];
      return `https://canvas.oneschoolglobal.com/courses/${courseId}/assignments/${assignmentId}`;
    }
    
    console.log('⚠️  Could not extract course/assignment IDs from:', calendarUrl);
    return '';
  } catch (error) {
    console.error('Error converting URL:', error);
    return '';
  }
};

// Detect task type from title
const detectTaskType = (title) => {
  const lower = title.toLowerCase();
  if (lower.includes('homework') || lower.includes('hw')) return 'homework';
  if (lower.includes('lab')) return 'lab';
  if (lower.includes('read')) return 'reading';
  if (lower.includes('essay') || lower.includes('writing')) return 'essay';
  if (lower.includes('project')) return 'project';
  if (lower.includes('quiz') || lower.includes('test') || lower.includes('exam')) return 'test-prep';
  return 'general';
};

// Advanced AI time estimation
const estimateTaskTime = async (task, userId) => {
  const { title, class: taskClass, url } = task;
  const lower = title.toLowerCase();
  
  console.log(`--- ESTIMATING TIME FOR: "${title}" ---`);
  
  // STEP 1: Not a Homeroom task (always 0 minutes)
  if (lower.includes('homeroom')) {
    console.log('✗ STEP 1: Not a Homeroom task (need 3+)');
    return 0;
  }
  console.log('✓ STEP 1: Not a Homeroom task');
  
  // STEP 2: Only 0 global completions (need 3+)
  try {
    const globalResult = await pool.query(
      `SELECT COUNT(*) as count, AVG(actual_time) as avg_time
       FROM tasks_completed
       WHERE url = $1`,
      [url]
    );
    
    const globalCount = parseInt(globalResult.rows[0]?.count || 0);
    const globalAvg = globalResult.rows[0]?.avg_time;
    
    console.log(`✗ STEP 2: Only ${globalCount} global completions (need 3+)`);
    
    if (globalCount >= 3 && globalAvg) {
      console.log(`✓ STEP 2: Using global average: ${Math.round(globalAvg)} minutes`);
      return Math.round(globalAvg);
    }
  } catch (error) {
    console.error('Error checking global completions:', error);
  }
  
  // STEP 3: Only 0 user completions (need 2+)
  try {
    const userResult = await pool.query(
      `SELECT COUNT(*) as count, AVG(actual_time) as avg_time
       FROM tasks_completed
       WHERE user_id = $1 AND url = $2`,
      [userId, url]
    );
    
    const userCount = parseInt(userResult.rows[0]?.count || 0);
    const userAvg = userResult.rows[0]?.avg_time;
    
    console.log(`✗ STEP 3: Only ${userCount} user completions (need 2+)`);
    
    if (userCount >= 2 && userAvg) {
      console.log(`✓ STEP 3: Using user average: ${Math.round(userAvg)} minutes`);
      return Math.round(userAvg);
    }
  } catch (error) {
    console.error('Error checking user completions:', error);
  }
  
  // STEP 4: No major project keywords found
  const projectKeywords = ['project', 'summative', 'assessment'];
  const hasProjectKeyword = projectKeywords.some(kw => lower.includes(kw));
  if (!hasProjectKeyword) {
    console.log('✗ STEP 4: No major project keywords found');
  } else {
    console.log('✓ STEP 4: Major project detected → 60 minutes');
    return 60;
  }
  
  // STEP 5: Not an OSGAccelerate Share task
  if (!lower.includes('[osg accelerate]')) {
    console.log('✗ STEP 5: Not an OSGAccelerate Share task');
  } else {
    console.log('✓ STEP 5: OSGAccelerate Share → 5 minutes');
    return 5;
  }
  
  // STEP 6: No medium-length keywords found
  const mediumKeywords = ['lab', 'formative'];
  const hasMediumKeyword = mediumKeywords.some(kw => lower.includes(kw));
  if (!hasMediumKeyword) {
    console.log('✗ STEP 6: No medium-length keywords found');
  } else {
    console.log('✓ STEP 6: Medium-length task detected → 30 minutes');
    return 30;
  }
  
  // STEP 7: Using default → 20 minutes
  console.log('✓ STEP 7: Using default → 20 minutes');
  return 20;
};

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!isValidOneSchoolEmail(email)) {
      return res.status(400).json({ error: 'Must use OneSchool Global email (@na.oneschoolglobal.com)' });
    }

    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const name = extractNameFromEmail(email);
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (email, password, name, is_new_user) VALUES ($1, $2, $3, $4) RETURNING id, email, name, is_new_user',
      [email, hashedPassword, name, true]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

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
      return res.status(400).json({ error: 'Must use OneSchool Global email (@na.oneschoolglobal.com)' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

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

// ============================================================================
// USER SETUP ROUTES
// ============================================================================

// Get user setup
app.get('/api/account/setup', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT grade, canvas_url, present_periods FROM users WHERE id = $1',
      [req.user.id]
    );

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
      grade: userResult.rows[0]?.grade || '',
      canvasUrl: userResult.rows[0]?.canvas_url || '',
      presentPeriods: userResult.rows[0]?.present_periods || '2-6',
      schedule
    });
  } catch (error) {
    console.error('Get setup error:', error);
    res.status(500).json({ error: 'Failed to get setup' });
  }
});

// Save user setup
app.post('/api/account/setup', authenticateToken, async (req, res) => {
  try {
    const { grade, canvasUrl, presentPeriods, schedule } = req.body;

    await pool.query(
      'UPDATE users SET grade = $1, canvas_url = $2, present_periods = $3, is_new_user = false WHERE id = $4',
      [grade, canvasUrl, presentPeriods, req.user.id]
    );

    await pool.query('DELETE FROM schedules WHERE user_id = $1', [req.user.id]);

    if (schedule) {
      for (const day in schedule) {
        for (const period in schedule[day]) {
          await pool.query(
            'INSERT INTO schedules (user_id, day, period, type) VALUES ($1, $2, $3, $4)',
            [req.user.id, day, parseInt(period), schedule[day][period]]
          );
        }
      }
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Save setup error:', error);
    res.status(500).json({ error: 'Failed to save setup' });
  }
});

// ============================================================================
// CALENDAR IMPORT ROUTES
// ============================================================================

// Fetch Canvas calendar
app.post('/api/calendar/fetch', authenticateToken, async (req, res) => {
  try {
    const { canvasUrl } = req.body;

    if (!canvasUrl) {
      return res.status(400).json({ error: 'Canvas URL is required' });
    }

    // Validate URL format
    if (!canvasUrl.includes('canvas.oneschoolglobal.com/feeds/calendars/')) {
      return res.status(400).json({ 
        error: 'Invalid Canvas URL format. Please use the calendar feed URL from Canvas.' 
      });
    }

    console.log('\n=== FETCHING CANVAS CALENDAR ===');
    console.log('URL:', canvasUrl);
    console.log('User:', req.user.id);

    let icsData;
    try {
      const response = await axios.get(canvasUrl, {
        timeout: 30000,
        headers: {
          'User-Agent': 'PlanAssist/2.0'
        }
      });
      console.log('✓ Calendar fetch successful, response status:', response.status);
      icsData = response.data;
    } catch (error) {
      console.error('❌ Error fetching calendar:', error.message);
      console.error('Error details:', {
        status: error.response?.status,
        statusText: error.response?.statusText,
        url: canvasUrl
      });
      return res.status(500).json({ 
        error: 'Failed to fetch calendar data. Please verify your Canvas URL is correct.',
        details: error.message 
      });
    }

    console.log('Parsing ICS data...');
    const events = await ical.async.parseICS(icsData);
    console.log(`✓ Parsed ${Object.keys(events).length} total events`);
    
    const tasks = [];
    
    // Calculate one month window from today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const oneMonthFromNow = new Date(today);
    oneMonthFromNow.setMonth(oneMonthFromNow.getMonth() + 1);

    console.log('\n=== PROCESSING CANVAS EVENTS ===');
    console.log(`Date range: ${today.toISOString()} to ${oneMonthFromNow.toISOString()}`);
    
    let processedCount = 0;
    let skippedCount = 0;
    
    for (const event of Object.values(events)) {
      if (event.type === 'VEVENT' && event.summary) {
        const eventDate = new Date(event.start || event.end || new Date());
        
        // Only include tasks within the next month
        if (eventDate >= today && eventDate <= oneMonthFromNow) {
          try {
            const title = extractTitle(event.summary);
            const taskClass = extractClass(event.summary);
            
            // Handle URL - ICS might have it in different formats
            let eventUrl = '';
            if (event.url) {
              if (typeof event.url === 'string') {
                eventUrl = event.url;
              } else if (event.url.val) {
                eventUrl = event.url.val; // Some ICS parsers wrap URL in an object
              }
            }
            
            const url = convertToAssignmentUrl(eventUrl);
            
            console.log(`\n[${processedCount + 1}] Processing: ${event.summary}`);
            console.log(`    Title: ${title}`);
            console.log(`    Class: ${taskClass}`);
            console.log(`    Raw URL: ${eventUrl || 'NONE'}`);
            console.log(`    Converted URL: ${url || 'NONE'}`);
            
            // Skip tasks without valid URLs (except Homeroom which we allow)
            if (!url && !taskClass.includes('Homeroom')) {
              console.log('    ⚠️  Skipping - no valid URL');
              skippedCount++;
              continue;
            }
            
            // Calculate AI estimate
            const estimatedTime = await estimateTaskTime({ title, class: taskClass, url }, req.user.id);
            
            tasks.push({
              title,
              segment: null, // Base tasks start with no segment
              class: taskClass,
              description: event.description || '',
              url: url || '', // Use empty string if no URL
              deadline: eventDate,
              estimatedTime
            });
            
            processedCount++;
          } catch (eventError) {
            console.error(`    ❌ Error processing event:`, eventError.message);
            skippedCount++;
          }
        }
      }
    }

    console.log(`\n=== PROCESSING COMPLETE ===`);
    console.log(`✓ Successfully processed: ${processedCount} tasks`);
    console.log(`⚠️  Skipped: ${skippedCount} events`);
    console.log(`Total tasks to import: ${tasks.length}\n`);

    // Update user's Canvas URL
    await pool.query(
      'UPDATE users SET canvas_url = $1 WHERE id = $2',
      [canvasUrl, req.user.id]
    );

    res.json({ tasks });
  } catch (error) {
    console.error('❌ Fetch calendar error:', error);
    console.error('Stack:', error.stack);
    res.status(500).json({ 
      error: 'Failed to fetch calendar',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// ============================================================================
// TASK MANAGEMENT ROUTES
// ============================================================================

// Get tasks (all incomplete tasks)
// FIXED: Added column aliasing for frontend compatibility
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        id,
        user_id,
        title,
        segment,
        class,
        description,
        url,
        deadline as due_date,
        estimated_time,
        user_estimated_time as user_estimate,
        accumulated_time,
        completed,
        priority_order,
        is_new,
        'general' as task_type
       FROM tasks 
       WHERE user_id = $1 AND completed = false
       ORDER BY priority_order ASC NULLS LAST, deadline ASC`,
      [req.user.id]
    );
    res.json(result.rows || []);
  } catch (error) {
    console.error('Get tasks error:', error);
    res.json([]);
  }
});

// Save tasks (bulk import from Canvas)
app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { tasks } = req.body;

    if (!Array.isArray(tasks)) {
      return res.status(400).json({ error: 'Tasks must be an array' });
    }

    // Get user's priority lock setting
    const userResult = await pool.query(
      'SELECT priority_locked FROM users WHERE id = $1',
      [req.user.id]
    );
    const priorityLocked = userResult.rows[0]?.priority_locked || false;

    // Get existing tasks to preserve user overrides
    const existingTasks = await pool.query(
      'SELECT title, segment, user_estimated_time, priority_order, accumulated_time FROM tasks WHERE user_id = $1',
      [req.user.id]
    );

    // Create map of existing tasks by title+segment
    const existingTaskMap = {};
    (existingTasks.rows || []).forEach(task => {
      const key = `${task.title}|||${task.segment || 'NULL'}`;
      existingTaskMap[key] = {
        userEstimatedTime: task.user_estimated_time,
        priorityOrder: task.priority_order,
        accumulatedTime: task.accumulated_time
      };
    });

    // Identify new tasks
    const existingKeys = new Set(Object.keys(existingTaskMap));
    const incomingKeys = new Set(tasks.map(t => `${t.title}|||${t.segment || 'NULL'}`));
    const newTaskKeys = new Set([...incomingKeys].filter(k => !existingKeys.has(k)));

    // Get max priority for appending new tasks
    const maxPriorityResult = await pool.query(
      'SELECT MAX(priority_order) as max_priority FROM tasks WHERE user_id = $1',
      [req.user.id]
    );
    let nextPriority = (maxPriorityResult.rows[0]?.max_priority || 0) + 1;

    // Clear existing incomplete tasks
    await pool.query('DELETE FROM tasks WHERE user_id = $1 AND completed = false', [req.user.id]);

    // Insert new tasks
    const insertedTasks = [];
    for (const task of tasks) {
      const key = `${task.title}|||${task.segment || 'NULL'}`;
      const existing = existingTaskMap[key];
      const isNew = newTaskKeys.has(key);
      
      // Determine priority order
      let priorityOrder = null;
      if (existing?.priorityOrder !== undefined) {
        priorityOrder = existing.priorityOrder;
      } else if (!priorityLocked) {
        priorityOrder = null; // Sort by deadline
      } else if (isNew) {
        priorityOrder = nextPriority++;
      }

      const result = await pool.query(
        `INSERT INTO tasks 
         (user_id, title, segment, class, description, url, deadline, estimated_time, user_estimated_time, accumulated_time, priority_order, is_new, completed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         RETURNING 
           id,
           user_id,
           title,
           segment,
           class,
           description,
           url,
           deadline as due_date,
           estimated_time,
           user_estimated_time as user_estimate,
           accumulated_time,
           completed,
           priority_order,
           is_new,
           'general' as task_type`,
        [
          req.user.id,
          task.title,
          task.segment || null,
          task.class,
          task.description || '',
          task.url,
          task.deadline,
          task.estimatedTime,
          existing?.userEstimatedTime || null,
          existing?.accumulatedTime || 0,
          priorityOrder,
          priorityLocked && isNew,
          false
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

// Split a task into segments
app.post('/api/tasks/:id/split', authenticateToken, async (req, res) => {
  try {
    const taskId = req.params.id;
    const { segments } = req.body; // Array of segment names: ["Part 1", "Part 2", "Part 3"]

    if (!Array.isArray(segments) || segments.length < 2) {
      return res.status(400).json({ error: 'Must provide at least 2 segments' });
    }

    // Get the original task
    const taskResult = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    if (taskResult.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    const originalTask = taskResult.rows[0];
    
    // Create new segment tasks
    const newSegments = [];
    for (const segmentName of segments) {
      // Build full segment path
      const fullSegment = originalTask.segment 
        ? `${originalTask.segment} - ${segmentName}`
        : segmentName;
      
      const result = await pool.query(
        `INSERT INTO tasks 
         (user_id, title, segment, class, description, url, deadline, estimated_time, user_estimated_time, accumulated_time, priority_order, is_new, completed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         RETURNING 
           id,
           user_id,
           title,
           segment,
           class,
           description,
           url,
           deadline as due_date,
           estimated_time,
           user_estimated_time as user_estimate,
           accumulated_time,
           completed,
           priority_order,
           is_new,
           'general' as task_type`,
        [
          req.user.id,
          originalTask.title, // Keep same title
          fullSegment,
          originalTask.class,
          originalTask.description,
          originalTask.url,
          originalTask.deadline,
          Math.floor(originalTask.estimated_time / segments.length), // Divide estimate
          originalTask.user_estimated_time ? Math.floor(originalTask.user_estimated_time / segments.length) : null,
          0, // Reset accumulated time
          null, // Let priority sort naturally
          false,
          false
        ]
      );
      
      newSegments.push(result.rows[0]);
    }

    // Delete the original task
    await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    res.json({ success: true, segments: newSegments });
  } catch (error) {
    console.error('Split task error:', error);
    res.status(500).json({ error: 'Failed to split task' });
  }
});

// Update task estimate (user override)
app.patch('/api/tasks/:id/estimate', authenticateToken, async (req, res) => {
  try {
    const { estimatedTime } = req.body;
    const result = await pool.query(
      `UPDATE tasks 
       SET user_estimated_time = $1 
       WHERE id = $2 AND user_id = $3
       RETURNING 
         id,
         user_id,
         title,
         segment,
         class,
         description,
         url,
         deadline as due_date,
         estimated_time,
         user_estimated_time as user_estimate,
         accumulated_time,
         completed,
         priority_order,
         is_new,
         'general' as task_type`,
      [estimatedTime, req.params.id, req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update estimate error:', error);
    res.status(500).json({ error: 'Failed to update estimate' });
  }
});

// Update tasks priority order
app.post('/api/tasks/reorder', authenticateToken, async (req, res) => {
  try {
    const { taskIds } = req.body;
    
    if (!Array.isArray(taskIds)) {
      return res.status(400).json({ error: 'taskIds must be an array' });
    }

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

// Delete task
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// Mark task complete and move to tasks_completed
app.post('/api/tasks/:id/complete', authenticateToken, async (req, res) => {
  try {
    const taskId = req.params.id;
    const { actualTime } = req.body;

    // Get the task
    const taskResult = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    if (taskResult.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    const task = taskResult.rows[0];
    const totalTime = task.accumulated_time + actualTime;

    // Insert into tasks_completed
    await pool.query(
      `INSERT INTO tasks_completed 
       (id, user_id, title, class, description, url, deadline, estimated_time, actual_time)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        task.id,
        req.user.id,
        task.title,
        task.class,
        task.description,
        task.url,
        task.deadline,
        task.user_estimated_time || task.estimated_time,
        totalTime
      ]
    );

    // Delete from tasks
    await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    // Check if there are other segments with the same title+url
    const otherSegments = await pool.query(
      'SELECT COUNT(*) as count FROM tasks WHERE user_id = $1 AND title = $2 AND url = $3',
      [req.user.id, task.title, task.url]
    );

    // If no other segments exist, consolidate completed segments in tasks_completed
    if (parseInt(otherSegments.rows[0].count) === 0) {
      const completedSegments = await pool.query(
        'SELECT * FROM tasks_completed WHERE user_id = $1 AND title = $2 AND url = $3',
        [req.user.id, task.title, task.url]
      );

      if (completedSegments.rows.length > 1) {
        // Consolidate: sum actual_time, keep first estimate
        const totalActual = completedSegments.rows.reduce((sum, s) => sum + s.actual_time, 0);
        const firstSegment = completedSegments.rows[0];

        // Delete all segments
        await pool.query(
          'DELETE FROM tasks_completed WHERE user_id = $1 AND title = $2 AND url = $3',
          [req.user.id, task.title, task.url]
        );

        // Insert consolidated record
        await pool.query(
          `INSERT INTO tasks_completed 
           (id, user_id, title, class, description, url, deadline, estimated_time, actual_time)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [
            firstSegment.id,
            req.user.id,
            task.title,
            task.class,
            task.description,
            task.url,
            task.deadline,
            firstSegment.estimated_time,
            totalActual
          ]
        );
      }
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Complete task error:', error);
    res.status(500).json({ error: 'Failed to complete task' });
  }
});

// Save partial completion (accumulated time)
app.post('/api/tasks/:id/partial', authenticateToken, async (req, res) => {
  try {
    const taskId = req.params.id;
    const { timeSpent } = req.body;

    const result = await pool.query(
      `UPDATE tasks 
       SET accumulated_time = accumulated_time + $1
       WHERE id = $2 AND user_id = $3
       RETURNING 
         id,
         user_id,
         title,
         segment,
         class,
         description,
         url,
         deadline as due_date,
         estimated_time,
         user_estimated_time as user_estimate,
         accumulated_time,
         completed,
         priority_order,
         is_new,
         'general' as task_type`,
      [timeSpent, taskId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Partial completion error:', error);
    res.status(500).json({ error: 'Failed to save partial completion' });
  }
});

// Get global estimate for a task
app.get('/api/tasks/global-estimate/:title', authenticateToken, async (req, res) => {
  try {
    const title = decodeURIComponent(req.params.title);
    
    const result = await pool.query(
      `SELECT AVG(actual_time) as estimate, COUNT(*) as count
       FROM tasks_completed
       WHERE title = $1`,
      [title]
    );

    if (result.rows[0] && parseInt(result.rows[0].count) >= 3) {
      res.json({ estimate: Math.round(result.rows[0].estimate) });
    } else {
      res.json({ estimate: null });
    }
  } catch (error) {
    console.error('Global estimate error:', error);
    res.json({ estimate: null });
  }
});

// ============================================================================
// SESSION MANAGEMENT ROUTES
// ============================================================================

// Save session state
app.post('/api/sessions/save-state', authenticateToken, async (req, res) => {
  try {
    const { day, period, remainingTime, currentTaskIndex, taskStartTime, completedTaskIds } = req.body;

    // Delete existing session state for this user
    await pool.query('DELETE FROM session_state WHERE user_id = $1', [req.user.id]);

    // Insert new session state
    await pool.query(
      `INSERT INTO session_state 
       (user_id, day, period, remaining_time, current_task_index, task_start_time, completed_task_ids)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [req.user.id, day, period, remainingTime, currentTaskIndex, taskStartTime, completedTaskIds]
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

    if (result.rows.length === 0) {
      return res.json({});
    }

    const state = result.rows[0];
    res.json({
      sessionId: state.id,
      day: state.day,
      period: state.period,
      remainingTime: state.remaining_time,
      currentTaskIndex: state.current_task_index,
      taskStartTime: state.task_start_time,
      completedTaskIds: state.completed_task_ids,
      savedAt: state.saved_at
    });
  } catch (error) {
    console.error('Get session state error:', error);
    res.json({});
  }
});

// Delete saved session state
app.delete('/api/sessions/saved-state', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM session_state WHERE user_id = $1', [req.user.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete session state error:', error);
    res.status(500).json({ error: 'Failed to delete session state' });
  }
});

// ============================================================================
// LEARNING/ANALYTICS ROUTES
// ============================================================================

// Get completion history
app.get('/api/learning', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        title as task_title,
        class as task_type,
        estimated_time,
        actual_time,
        completed_at
       FROM tasks_completed 
       WHERE user_id = $1 
       ORDER BY completed_at DESC`,
      [req.user.id]
    );
    res.json(result.rows || []);
  } catch (error) {
    console.error('Get learning error:', error);
    res.json([]);
  }
});

// ============================================================================
// USER SETTINGS ROUTES
// ============================================================================

// Get priority lock status
app.get('/api/user/priority-lock', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT priority_locked FROM users WHERE id = $1',
      [req.user.id]
    );
    res.json({ locked: result.rows[0]?.priority_locked || false });
  } catch (error) {
    console.error('Get priority lock error:', error);
    res.json({ locked: false });
  }
});

// Set priority lock status
app.post('/api/user/priority-lock', authenticateToken, async (req, res) => {
  try {
    const { locked } = req.body;
    await pool.query(
      'UPDATE users SET priority_locked = $1 WHERE id = $2',
      [locked, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Set priority lock error:', error);
    res.status(500).json({ error: 'Failed to set priority lock' });
  }
});

// ============================================================================
// FEEDBACK ROUTE
// ============================================================================

app.post('/api/feedback', authenticateToken, async (req, res) => {
  try {
    const { feedback, userEmail, userName } = req.body;
    
    await pool.query(
      'INSERT INTO feedback (user_id, user_email, user_name, feedback_text) VALUES ($1, $2, $3, $4)',
      [req.user.id, userEmail, userName, feedback]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).json({ error: 'Failed to save feedback' });
  }
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log(`🚀 PlanAssist API running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});
