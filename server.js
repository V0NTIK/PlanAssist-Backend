// PlanAssist - COMPLETELY REDESIGNED Backend API
// server.js - New title/segment system with advanced AI estimation

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
      return `https://canvas.oneschoolglobal.com/courses/${courseMatch[1]}/assignments/${assignmentMatch[1]}`;
    }
  } catch (error) {
    console.error('Error converting URL:', error.message);
  }
  
  return calendarUrl; // Return original if parsing fails
};

// ============================================================================
// NEW AI TASK TIME ESTIMATION ALGORITHM
// ============================================================================

const estimateTaskTime = async (task, userId) => {
  const { title, class: taskClass, url } = task;
  
  console.log(`\n=== ESTIMATING TIME FOR: "${title}" ===`);
  console.log(`Class: ${taskClass}`);
  console.log(`URL: ${url}`);
  
  // STEP 1: Check for Homeroom tasks
  if (taskClass.includes('Homeroom')) {
    console.log('✓ STEP 1: Homeroom task detected → 0 minutes');
    return 0;
  }
  console.log('✗ STEP 1: Not a Homeroom task');
  
  // STEP 2: Check for 3+ completions of this exact URL (global)
  try {
    const globalResult = await pool.query(
      `SELECT AVG(actual_time)::INTEGER as avg_time, COUNT(*) as count
       FROM tasks_completed 
       WHERE url = $1`,
      [url]
    );
    
    if (globalResult.rows[0] && globalResult.rows[0].count >= 3) {
      const estimate = globalResult.rows[0].avg_time;
      console.log(`✓ STEP 2: Found ${globalResult.rows[0].count} global completions → ${estimate} minutes`);
      return estimate;
    }
    console.log(`✗ STEP 2: Only ${globalResult.rows[0]?.count || 0} global completions (need 3+)`);
  } catch (error) {
    console.error('Error in Step 2:', error.message);
  }
  
  // STEP 3: Check for 2+ completions with matching title prefix (user-specific + same class)
  try {
    // Extract first 50% of words from title (round up)
    const words = title.split(' ');
    const halfWords = Math.ceil(words.length * 0.5);
    const titlePrefix = words.slice(0, halfWords).join(' ');
    
    console.log(`  Title prefix (first 50%): "${titlePrefix}"`);
    
    const userResult = await pool.query(
      `SELECT AVG(actual_time)::INTEGER as avg_time, COUNT(*) as count
       FROM tasks_completed 
       WHERE user_id = $1 
       AND class = $2
       AND title LIKE $3`,
      [userId, taskClass, `${titlePrefix}%`]
    );
    
    if (userResult.rows[0] && userResult.rows[0].count >= 2) {
      const estimate = userResult.rows[0].avg_time;
      console.log(`✓ STEP 3: Found ${userResult.rows[0].count} user completions with matching prefix → ${estimate} minutes`);
      return estimate;
    }
    console.log(`✗ STEP 3: Only ${userResult.rows[0]?.count || 0} user completions (need 2+)`);
  } catch (error) {
    console.error('Error in Step 3:', error.message);
  }
  
  // STEP 4: Check for major project keywords
  const projectKeywords = ['Project', 'Essay', 'Lab', 'Exam', 'Test', 'Assessment', 'Summative'];
  for (const keyword of projectKeywords) {
    if (title.includes(keyword)) {
      console.log(`✓ STEP 4: Found keyword "${keyword}" → 60 minutes`);
      return 60;
    }
  }
  console.log('✗ STEP 4: No major project keywords found');
  
  // STEP 5: Check for OSGAccelerate Share tasks
  if (title.includes('Share') && (taskClass.includes('OSGAccelerate') || taskClass.includes('OSG Accelerate'))) {
    console.log('✓ STEP 5: OSGAccelerate Share task → 5 minutes');
    return 5;
  }
  console.log('✗ STEP 5: Not an OSGAccelerate Share task');
  
  // STEP 6: Check for medium-length task keywords
  const mediumKeywords = ['Discussion', 'Chapters', 'Gizmos', 'IXL', 'Quiz', 'Worksheet'];
  for (const keyword of mediumKeywords) {
    if (title.includes(keyword)) {
      console.log(`✓ STEP 6: Found keyword "${keyword}" → 30 minutes`);
      return 30;
    }
  }
  console.log('✗ STEP 6: No medium-length keywords found');
  
  // STEP 7: Default estimate
  console.log('✓ STEP 7: Using default → 20 minutes');
  return 20;
};

// ============================================================================
// AUTH ROUTES
// ============================================================================

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

// ============================================================================
// ACCOUNT SETUP ROUTES
// ============================================================================

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

// ============================================================================
// CANVAS CALENDAR IMPORT
// ============================================================================

// Fetch Canvas calendar and import tasks
app.post('/api/calendar/fetch', authenticateToken, async (req, res) => {
  try {
    const { canvasUrl } = req.body;
    
    console.log('\n=== CALENDAR FETCH REQUEST ===');
    console.log('User ID:', req.user.id);
    console.log('Canvas URL:', canvasUrl);
    
    const isValidCanvasUrl = canvasUrl && 
      (canvasUrl.includes('instructure.com/feeds/calendars') || 
       canvasUrl.includes('oneschoolglobal.com/feeds/calendars'));
    
    if (!isValidCanvasUrl) {
      console.log('❌ Invalid Canvas URL format');
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
        
        // Canvas deadlines are stored as 11:59 PM EST (23:59:00-05:00)
        // In UTC, this becomes 04:59:00 (next day) or 05:59:00 depending on DST
        // We need to detect these early-morning UTC times and shift back to the previous day
        
        const utcHours = eventDate.getUTCHours();
        const utcMinutes = eventDate.getUTCMinutes();
        
        // If it's between midnight and 6 AM UTC, it's likely an 11:59 PM EST deadline from previous day
        let normalizedDate;
        if (utcHours >= 0 && utcHours < 6) {
          // Shift back by one day and set to 11:59 PM
          normalizedDate = new Date(
            eventDate.getUTCFullYear(),
            eventDate.getUTCMonth(),
            eventDate.getUTCDate() - 1,  // Previous day
            23, 59, 0, 0
          );
        } else {
          // Regular date - normalize to end of day (11:59 PM)
          normalizedDate = new Date(
            eventDate.getUTCFullYear(),
            eventDate.getUTCMonth(),
            eventDate.getUTCDate(),
            23, 59, 0, 0
          );
        }
        
        // Only include tasks within the next month
        if (normalizedDate >= today && normalizedDate <= oneMonthFromNow) {
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
              deadline: normalizedDate,
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
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM tasks 
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
         RETURNING *`,
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
         RETURNING *`,
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
    const { userEstimate } = req.body;
    const taskId = req.params.id;

    await pool.query(
      'UPDATE tasks SET user_estimated_time = $1 WHERE id = $2 AND user_id = $3',
      [userEstimate, taskId, req.user.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Update task estimate error:', error);
    res.status(500).json({ error: 'Failed to update estimate' });
  }
});

// Reorder tasks
app.post('/api/tasks/reorder', authenticateToken, async (req, res) => {
  try {
    const { taskOrder } = req.body;

    if (!Array.isArray(taskOrder)) {
      return res.status(400).json({ error: 'taskOrder must be an array' });
    }

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

// Clear new task flags
app.post('/api/tasks/clear-new-flags', authenticateToken, async (req, res) => {
  try {
    const { taskIds } = req.body;

    if (!Array.isArray(taskIds) || taskIds.length === 0) {
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

// Manual task completion (checkbox) - Just deletes the task
app.patch('/api/tasks/:id/complete', authenticateToken, async (req, res) => {
  try {
    const taskId = req.params.id;

    // Verify task exists
    const taskResult = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    if (taskResult.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    // Simply delete the task - no record keeping for manual completions
    await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Complete task error:', error);
    res.status(500).json({ error: 'Failed to complete task' });
  }
});

// ============================================================================
// SESSION AND COMPLETION ROUTES
// ============================================================================

// Save session state
app.post('/api/sessions/saved-state', authenticateToken, async (req, res) => {
  try {
    const { sessionId, day, period, remainingTime, currentTaskIndex, taskStartTime, completedTaskIds } = req.body;
    
    await pool.query('DELETE FROM session_state WHERE user_id = $1', [req.user.id]);
    
    await pool.query(
      `INSERT INTO session_state (user_id, day, period, remaining_time, current_task_index, task_start_time, completed_task_ids, saved_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)`,
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
      `SELECT * FROM session_state WHERE user_id = $1`,
      [req.user.id]
    );
    
    if (result.rows.length > 0) {
      const state = result.rows[0];
      res.json({
        sessionId: `${state.day}-${state.period}`,
        day: state.day,
        period: state.period,
        remainingTime: state.remaining_time,
        currentTaskIndex: state.current_task_index,
        taskStartTime: state.task_start_time,
        completedTaskIds: state.completed_task_ids || [],
        savedAt: state.saved_at
      });
    } else {
      res.json({});
    }
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

// Complete a task
app.post('/api/tasks/:taskId/complete', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { timeSpent } = req.body;
    
    const taskResult = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    
    if (taskResult.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    const task = taskResult.rows[0];
    
    await pool.query(
      `INSERT INTO tasks_completed (id, user_id, title, class, description, url, deadline, estimated_time, actual_time, completed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)`,
      [
        task.id,
        req.user.id,
        task.title,
        task.class,
        task.description,
        task.url,
        task.deadline,
        task.user_estimated_time || task.estimated_time,
        timeSpent
      ]
    );
    
    await pool.query('DELETE FROM tasks WHERE id = $1 AND user_id = $2', [taskId, req.user.id]);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Complete task error:', error);
    res.status(500).json({ error: 'Failed to complete task' });
  }
});

// Update task partial time (accumulated_time)
app.patch('/api/tasks/:taskId/partial', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { accumulatedTime } = req.body;
    
    await pool.query(
      'UPDATE tasks SET accumulated_time = $1 WHERE id = $2 AND user_id = $3',
      [accumulatedTime, taskId, req.user.id]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Update partial time error:', error);
    res.status(500).json({ error: 'Failed to update partial time' });
  }
});

// ============================================================================
// LEARNING/ANALYTICS ROUTE
// ============================================================================

// Get completion history for learning analytics
app.get('/api/learning', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT title as task_title, class as task_type, estimated_time, actual_time, completed_at
       FROM tasks_completed
       WHERE user_id = $1
       ORDER BY completed_at DESC`,
      [req.user.id]
    );
    res.json(result.rows || []);
  } catch (error) {
    console.error('Get learning data error:', error);
    res.json([]);
  }
});

// ============================================================================
// FEEDBACK ROUTE
// ============================================================================

app.post('/api/feedback', authenticateToken, async (req, res) => {
  try {
    const { feedback, userEmail, userName } = req.body;

    if (!feedback || feedback.trim().length === 0) {
      return res.status(400).json({ error: 'Feedback cannot be empty' });
    }

    await pool.query(
      'INSERT INTO feedback (user_id, user_email, user_name, feedback_text) VALUES ($1, $2, $3, $4)',
      [req.user.id, userEmail, userName, feedback]
    );

    res.json({ success: true, message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).json({ error: 'Failed to submit feedback' });
  }
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      status: 'ok', 
      message: 'PlanAssist API v2.0 - Title/Segment System',
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

// ============================================================================
// NOTES AND WORKSPACE ROUTES
// ============================================================================

// Get notes for a task
app.get('/api/tasks/:taskId/notes', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    
    const result = await pool.query(
      'SELECT notes FROM notes WHERE task_id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    
    if (result.rows.length > 0) {
      res.json({ notes: result.rows[0].notes });
    } else {
      res.json({ notes: '' });
    }
  } catch (error) {
    console.error('Get notes error:', error);
    res.status(500).json({ error: 'Failed to get notes' });
  }
});

// Save notes for a task
app.post('/api/tasks/:taskId/notes', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { notes } = req.body;
    
    // Upsert notes
    await pool.query(
      `INSERT INTO notes (task_id, user_id, notes, created_at, updated_at)
       VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
       ON CONFLICT (task_id, user_id)
       DO UPDATE SET notes = $3, updated_at = CURRENT_TIMESTAMP`,
      [taskId, req.user.id, notes]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Save notes error:', error);
    res.status(500).json({ error: 'Failed to save notes' });
  }
});

// ============================================================================
// CANVAS IFRAME PROXY - Bypass X-Frame-Options
// ============================================================================

app.get('/api/proxy-canvas', async (req, res) => {
  try {
    const { url, token } = req.query;
    
    if (!url) {
      return res.status(400).json({ error: 'URL parameter is required' });
    }
    
    if (!token) {
      return res.status(401).json({ error: 'Token parameter is required' });
    }
    
    // Verify the token
    try {
      jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // Validate it's a Canvas URL for security
    if (!url.includes('canvas.oneschoolglobal.com')) {
      return res.status(403).json({ error: 'Only Canvas URLs are allowed' });
    }
    
    console.log('🔄 Proxying Canvas URL:', url);
    
    // Fetch the Canvas page
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none'
      },
      maxRedirects: 5,
      validateStatus: function (status) {
        return status >= 200 && status < 400;
      }
    });
    
    let html = response.data;
    
    // More aggressive URL fixing with multiple patterns
    // Fix href attributes
    html = html.replace(/href=["']\/(?!\/)/g, 'href="https://canvas.oneschoolglobal.com/');
    html = html.replace(/href=["']\/\//g, 'href="https://');
    
    // Fix src attributes
    html = html.replace(/src=["']\/(?!\/)/g, 'src="https://canvas.oneschoolglobal.com/');
    html = html.replace(/src=["']\/\//g, 'src="https://');
    
    // Fix action attributes
    html = html.replace(/action=["']\/(?!\/)/g, 'action="https://canvas.oneschoolglobal.com/');
    
    // Fix CSS url() references
    html = html.replace(/url\(["']?\/(?!\/)/g, 'url("https://canvas.oneschoolglobal.com/');
    html = html.replace(/url\(["']?\/\//g, 'url("https://');
    
    // Fix data attributes
    html = html.replace(/data-src=["']\/(?!\/)/g, 'data-src="https://canvas.oneschoolglobal.com/');
    html = html.replace(/data-url=["']\/(?!\/)/g, 'data-url="https://canvas.oneschoolglobal.com/');
    
    // Fix srcset attributes
    html = html.replace(/srcset=["']\/(?!\/)/g, 'srcset="https://canvas.oneschoolglobal.com/');
    
    // Inject a more comprehensive base tag and CSP override
    const headInjection = `<head>
    <base href="https://canvas.oneschoolglobal.com/">
    <meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline';">
    <style>
      /* Ensure page renders properly */
      html, body { 
        margin: 0; 
        padding: 0; 
        width: 100%; 
        height: 100%;
        overflow: auto;
      }
    </style>`;
    
    html = html.replace('<head>', headInjection);
    
    // Set headers to allow iframe embedding and prevent CORB issues
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('X-Frame-Options', 'ALLOWALL');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'unsafe-none');
    
    res.send(html);
    
  } catch (error) {
    console.error('Canvas proxy error:', error.message);
    
    // Send a user-friendly error page
    const errorHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Canvas Loading Error</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
          }
          .error-box {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            max-width: 500px;
            text-align: center;
          }
          .error-title {
            color: #e53e3e;
            font-size: 1.5rem;
            margin-bottom: 1rem;
          }
          .error-message {
            color: #4a5568;
            margin-bottom: 1.5rem;
          }
          .error-button {
            background: #805ad5;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            text-decoration: none;
            display: inline-block;
          }
        </style>
      </head>
      <body>
        <div class="error-box">
          <div class="error-title">Failed to Load Canvas</div>
          <div class="error-message">
            ${error.message || 'An error occurred while loading the Canvas page.'}
          </div>
          <a href="${req.query.url}" target="_blank" class="error-button">
            Open in New Tab Instead
          </a>
        </div>
      </body>
      </html>
    `;
    
    res.status(500).setHeader('Content-Type', 'text/html').send(errorHtml);
  }
});

// ============================================================================
// CANVAS RESOURCE PROXY - For CSS, JS, Images
// ============================================================================

app.get('/api/proxy-resource', async (req, res) => {
  try {
    const { url, token } = req.query;
    
    if (!url || !token) {
      return res.status(400).json({ error: 'URL and token required' });
    }
    
    // Verify token
    try {
      jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // Only allow Canvas resources
    if (!url.includes('canvas.oneschoolglobal.com') && !url.includes('instructure.com')) {
      return res.status(403).json({ error: 'Only Canvas resources allowed' });
    }
    
    console.log('📦 Proxying Canvas resource:', url);
    
    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://canvas.oneschoolglobal.com/'
      },
      maxRedirects: 5
    });
    
    // Forward the content type
    const contentType = response.headers['content-type'] || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    
    res.send(response.data);
    
  } catch (error) {
    console.error('Resource proxy error:', error.message);
    res.status(500).send('Failed to fetch resource');
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`\n==============================================`);
  console.log(`  PlanAssist API v2.0 - REDESIGNED`);
  console.log(`  Server running on port ${PORT}`);
  console.log(`  Title/Segment System Active`);
  console.log(`  Advanced AI Estimation Enabled`);
  console.log(`  Canvas Proxy Enabled`);
  console.log(`==============================================\n`);
});
