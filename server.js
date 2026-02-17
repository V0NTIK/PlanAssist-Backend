// PlanAssist - COMPLETELY REDESIGNED Backend API
// server.js - New title/segment system with advanced AI estimation

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const axios = require('axios');
const ICAL = require('ical.js');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: [
    'https://planassist.onrender.com',
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

// JWT Secret - ENFORCE in production
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('❌ FATAL ERROR: JWT_SECRET environment variable is required in production');
    process.exit(1);
  } else {
    console.warn('⚠️  WARNING: Using default JWT_SECRET for development. Set JWT_SECRET env variable for production!');
    JWT_SECRET = 'dev-only-insecure-secret-change-for-production';
  }
}

// Encryption key for Canvas API tokens - ENFORCE in production
let ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
  if (process.env.NODE_ENV === 'production') {
    console.error('❌ FATAL ERROR: ENCRYPTION_KEY environment variable is required in production');
    process.exit(1);
  } else {
    console.warn('⚠️  WARNING: Using default ENCRYPTION_KEY for development. Set ENCRYPTION_KEY env variable for production!');
    // Must be 32 bytes for AES-256
    ENCRYPTION_KEY = 'dev-only-insecure-encryption-key-32-chars!!';
  }
}

// Ensure encryption key is 32 bytes
const ENCRYPTION_KEY_BUFFER = Buffer.from(ENCRYPTION_KEY.padEnd(32, '0').slice(0, 32));

// ============================================================================
// ENCRYPTION HELPERS FOR CANVAS API TOKENS
// ============================================================================

// Encrypt Canvas API token
const encryptToken = (token) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY_BUFFER, iv);
  
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encryptedToken: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
};

// Decrypt Canvas API token
const decryptToken = (encryptedToken, ivHex, authTagHex) => {
  try {
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY_BUFFER, iv);
    
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Token decryption failed:', error.message);
    return null;
  }
};

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

// Validate grade (must be 7-12)
const isValidGrade = (grade) => {
  const validGrades = ['7', '8', '9', '10', '11', '12'];
  return validGrades.includes(String(grade));
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
      'SELECT grade, canvas_api_token, canvas_api_token_iv, present_periods FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    
    // Decrypt Canvas API token if it exists
    let canvasApiToken = '';
    if (user.canvas_api_token && user.canvas_api_token_iv) {
      // For AES-GCM, the auth tag is appended to the encrypted token
      const encryptedParts = user.canvas_api_token.split(':');
      if (encryptedParts.length === 2) {
        const decrypted = decryptToken(encryptedParts[0], user.canvas_api_token_iv, encryptedParts[1]);
        if (decrypted) {
          canvasApiToken = decrypted;
        }
      }
    }

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
      canvasApiToken: canvasApiToken,
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
    const { grade, canvasApiToken, presentPeriods, schedule } = req.body;

    // Validate grade before saving
    if (!isValidGrade(grade)) {
      return res.status(400).json({ error: 'Grade must be one of: 7, 8, 9, 10, 11, or 12' });
    }
    
    // Encrypt Canvas API token if provided
    let encryptedToken = null;
    let iv = null;
    
    if (canvasApiToken && canvasApiToken.trim()) {
      const encrypted = encryptToken(canvasApiToken.trim());
      // Store encrypted token with auth tag appended (format: encrypted:authTag)
      encryptedToken = `${encrypted.encryptedToken}:${encrypted.authTag}`;
      iv = encrypted.iv;
    }

    await pool.query(
      'UPDATE users SET grade = $1, canvas_api_token = $2, canvas_api_token_iv = $3, present_periods = $4, is_new_user = false WHERE id = $5',
      [grade, encryptedToken, iv, presentPeriods, req.user.id]
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

    console.log('Parsing ICS data with ical.js...');
    
    // Parse using ical.js (same as the working viewer)
    const jcalData = ICAL.parse(icsData);
    const comp = new ICAL.Component(jcalData);
    const vevents = comp.getAllSubcomponents('vevent');
    
    console.log(`✓ Parsed ${vevents.length} events from ICS`);
    
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
    
    for (const vevent of vevents) {
      try {
        const event = new ICAL.Event(vevent);
        
        const summary = event.summary;
        if (!summary) {
          skippedCount++;
          continue;
        }
        
        console.log(`\n[${processedCount + 1}] Processing: ${summary}`);
        
        // Get DTSTART - this is the key part that ical.js handles correctly
        const dtstart = vevent.getFirstPropertyValue('dtstart');
        const dtend = vevent.getFirstPropertyValue('dtend');
        
        // DEBUG: For Homeroom tasks, show extra details
        const isHomeroom = summary.includes('Homeroom');
        if (isHomeroom) {
          console.log('    🔍 HOMEROOM TASK - Extra debugging:');
          const dtstartProp = vevent.getFirstProperty('dtstart');
          const dtendProp = vevent.getFirstProperty('dtend');
          
          if (dtstartProp) {
            console.log('    Raw DTSTART property:', dtstartProp.toICALString());
            console.log('    DTSTART type:', dtstartProp.type);
            console.log('    DTSTART isDate:', dtstart ? dtstart.isDate : 'N/A');
          }
          
          if (dtendProp) {
            console.log('    Raw DTEND property:', dtendProp.toICALString());
            console.log('    DTEND type:', dtendProp.type);
            console.log('    DTEND isDate:', dtend ? dtend.isDate : 'N/A');
            if (dtend && !dtend.isDate) {
              console.log('    DTEND has time! Using DTEND instead of DTSTART');
            }
          }
        }
        
        if (!dtstart) {
          console.log('    ⚠️  No DTSTART found');
          skippedCount++;
          continue;
        }
        
        // Use DTEND if DTSTART is date-only but DTEND has time (Canvas quiz behavior)
        let effectiveDtstart = dtstart;
        if (dtstart.isDate && dtend && !dtend.isDate) {
          console.log('    ℹ️  Using DTEND instead of DTSTART (quiz due time)');
          effectiveDtstart = dtend;
        }
        
        // Check if this is a date-only or datetime
        let deadlineDate = null;
        let deadlineTime = null;
        
        if (effectiveDtstart.isDate) {
          // Date-only (no time component)
          deadlineDate = `${effectiveDtstart.year}-${String(effectiveDtstart.month).padStart(2, '0')}-${String(effectiveDtstart.day).padStart(2, '0')}`;
          deadlineTime = null;
          console.log(`    ✓ Date-only: ${deadlineDate}`);
        } else {
          // Has time component
          const utcTime = effectiveDtstart.toJSDate(); // Converts to JavaScript Date in UTC
          
          const year = utcTime.getUTCFullYear();
          const month = String(utcTime.getUTCMonth() + 1).padStart(2, '0');
          const day = String(utcTime.getUTCDate()).padStart(2, '0');
          const hour = String(utcTime.getUTCHours()).padStart(2, '0');
          const minute = String(utcTime.getUTCMinutes()).padStart(2, '0');
          const second = String(utcTime.getUTCSeconds()).padStart(2, '0');
          
          deadlineDate = `${year}-${month}-${day}`;
          deadlineTime = `${hour}:${minute}:${second}`;
          console.log(`    ✓ DateTime: ${deadlineDate}T${deadlineTime}Z`);
        }
        
        // Create a Date object for filtering
        const parsedDate = deadlineTime 
          ? new Date(`${deadlineDate}T${deadlineTime}Z`)
          : new Date(`${deadlineDate}T00:00:00Z`);
        
        // Only include tasks within the next month
        if (parsedDate >= today && parsedDate <= oneMonthFromNow) {
          const title = extractTitle(summary);
          const taskClass = extractClass(summary);
          
          // Extract URL and description using ical.js
          const url = vevent.getFirstPropertyValue('url') || '';
          const description = vevent.getFirstPropertyValue('description') || '';
          
          // Convert URL
          const convertedUrl = convertToAssignmentUrl(url);
          
          console.log(`    Title: ${title}`);
          console.log(`    Class: ${taskClass}`);
          console.log(`    Raw URL: ${url || 'NONE'}`);
          console.log(`    Converted URL: ${convertedUrl || 'NONE'}`);
          
          // Skip tasks without valid URLs (except Homeroom which we allow)
          if (!convertedUrl && !taskClass.includes('Homeroom')) {
            console.log('    ⚠️  Skipping - no valid URL');
            skippedCount++;
            continue;
          }
          
          // Calculate AI estimate
          const estimatedTime = await estimateTaskTime({ title, class: taskClass, url: convertedUrl }, req.user.id);
          
          tasks.push({
            title,
            segment: null, // Base tasks start with no segment
            class: taskClass,
            description: description || '',
            url: convertedUrl || '', // Use empty string if no URL
            deadlineDate: deadlineDate, // DATE field (YYYY-MM-DD)
            deadlineTime: deadlineTime, // TIME field (HH:MM:SS) or null
            estimatedTime
          });
          
          processedCount++;
        } else {
          skippedCount++;
        }
      } catch (eventError) {
        console.error(`    ❌ Error processing event:`, eventError.message);
        skippedCount++;
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
       WHERE user_id = $1 AND completed = false AND deleted = false
       ORDER BY priority_order ASC NULLS LAST, deadline_date ASC, deadline_time ASC NULLS LAST`,
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

    console.log(`\n=== SYNC OPERATION: Processing ${tasks.length} tasks from ICS ===`);

    // Track what we do for logging
    let updatedCount = 0;
    let newCount = 0;
    const insertedTasks = [];

    for (const incomingTask of tasks) {
      // Check if this URL already exists in the database (including deleted tasks)
      const existingTasksResult = await pool.query(
        'SELECT * FROM tasks WHERE user_id = $1 AND url = $2',
        [req.user.id, incomingTask.url]
      );

      if (existingTasksResult.rows.length > 0) {
        // URL EXISTS - Update existing task(s) with Canvas data, preserve user modifications
        console.log(`\n[UPDATE] Found ${existingTasksResult.rows.length} existing task(s) with URL: ${incomingTask.url}`);
        
        for (const existingTask of existingTasksResult.rows) {
          // Update only Canvas-controlled fields, preserve user work
          await pool.query(
            `UPDATE tasks SET 
              title = $1,
              description = $2,
              estimated_time = $3,
              completed = $4,
              class = $5,
              url = $6,
              deadline_date = $7,
              deadline_time = $8
             WHERE id = $9 AND user_id = $10`,
            [
              incomingTask.title,
              incomingTask.description || '',
              incomingTask.estimatedTime,
              false, // Always false during sync
              incomingTask.class,
              incomingTask.url,
              incomingTask.deadlineDate,
              incomingTask.deadlineTime,
              existingTask.id,
              req.user.id
            ]
          );
          
          console.log(`  ✓ Updated task ID ${existingTask.id}: "${existingTask.title}"`);
          console.log(`    Preserved: priority_order=${existingTask.priority_order}, segment="${existingTask.segment}", user_estimated_time=${existingTask.user_estimated_time}, accumulated_time=${existingTask.accumulated_time}, deleted=${existingTask.deleted}`);
          updatedCount++;
        }

        // Fetch the updated tasks to return (only non-deleted ones)
        const updatedTasksResult = await pool.query(
          'SELECT * FROM tasks WHERE user_id = $1 AND url = $2 AND deleted = false',
          [req.user.id, incomingTask.url]
        );
        insertedTasks.push(...updatedTasksResult.rows);

      } else {
        // URL DOESN'T EXIST - Import as new task
        console.log(`\n[NEW] Importing new task: ${incomingTask.title}`);
        
        // Get max priority for appending new tasks
        const maxPriorityResult = await pool.query(
          'SELECT MAX(priority_order) as max_priority FROM tasks WHERE user_id = $1 AND deleted = false',
          [req.user.id]
        );
        const nextPriority = (maxPriorityResult.rows[0]?.max_priority || 0) + 1;

        const result = await pool.query(
          `INSERT INTO tasks 
           (user_id, title, segment, class, description, url, deadline_date, deadline_time, estimated_time, user_estimated_time, accumulated_time, priority_order, is_new, completed, deleted)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
           RETURNING *`,
          [
            req.user.id,
            incomingTask.title,
            null, // New tasks start with no segment
            incomingTask.class,
            incomingTask.description || '',
            incomingTask.url,
            incomingTask.deadlineDate,
            incomingTask.deadlineTime,
            incomingTask.estimatedTime,
            null, // No user override yet
            0, // No accumulated time yet
            nextPriority, // Append to end
            true, // Mark as new
            false, // Not completed
            false // Not deleted
          ]
        );
        
        insertedTasks.push(result.rows[0]);
        newCount++;
        console.log(`  ✓ Created task ID ${result.rows[0].id} with priority ${nextPriority}`);
      }
    }

    // === CLEANUP PAST DUE TASKS ===
    // After sync, mark any incomplete tasks that are past their deadline as deleted
    // This prevents old unfinished tasks from cluttering the task list
    console.log(`\n=== CLEANING UP PAST DUE TASKS ===`);
    
    // Define today's date at midnight for comparison
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayDateStr = today.toISOString().split('T')[0]; // YYYY-MM-DD format
    
    const cleanupResult = await pool.query(
      `UPDATE tasks 
       SET deleted = true 
       WHERE user_id = $1 
         AND completed = false 
         AND deleted = false 
         AND deadline_date < $2
       RETURNING id, title, deadline_date`,
      [req.user.id, todayDateStr]
    );
    
    const cleanedUpCount = cleanupResult.rows.length;
    if (cleanedUpCount > 0) {
      console.log(`Marked ${cleanedUpCount} past-due incomplete tasks as deleted:`);
      cleanupResult.rows.forEach(task => {
        console.log(`  - "${task.title}" (due: ${task.deadline_date})`);
      });
    } else {
      console.log('No past-due tasks to clean up');
    }

    console.log(`\n=== SYNC COMPLETE ===`);
    console.log(`Updated: ${updatedCount} existing tasks`);
    console.log(`Added: ${newCount} new tasks`);
    console.log(`Cleaned up: ${cleanedUpCount} past-due tasks`);
    console.log(`Total returned: ${insertedTasks.length} tasks\n`);

    res.json({ 
      success: true, 
      tasks: insertedTasks, 
      stats: { 
        updated: updatedCount, 
        new: newCount,
        cleaned: cleanedUpCount
      } 
    });
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
         (user_id, title, segment, class, description, url, deadline_date, deadline_time, estimated_time, user_estimated_time, accumulated_time, priority_order, is_new, completed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         RETURNING *`,
        [
          req.user.id,
          originalTask.title, // Keep same title
          fullSegment,
          originalTask.class,
          originalTask.description,
          originalTask.url,
          originalTask.deadline_date,
          originalTask.deadline_time,
          Math.floor(originalTask.estimated_time / segments.length), // Divide estimate
          originalTask.user_estimated_time ? Math.floor(originalTask.user_estimated_time / segments.length) : null,
          0, // Reset accumulated time
          null, // Let priority sort naturally - will be set when user adds from sidebar
          true, // Mark as NEW so it appears in sidebar for prioritization
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

    // Update priority orders, but only for non-deleted tasks
    const updatePromises = taskOrder.map((taskId, index) =>
      pool.query(
        'UPDATE tasks SET priority_order = $1 WHERE id = $2 AND user_id = $3 AND deleted = false',
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

// Manual task completion (checkbox) - Marks as deleted to preserve URL history
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

    // Mark task as deleted and clear priority_order
    // This preserves the URL in the database so it won't be re-imported during sync
    await pool.query(
      'UPDATE tasks SET deleted = true, priority_order = NULL WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Complete task error:', error);
    res.status(500).json({ error: 'Failed to complete task' });
  }
});

// Uncomplete task - Restore a deleted task
app.patch('/api/tasks/:id/uncomplete', authenticateToken, async (req, res) => {
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

    // Restore task by unmarking deleted and restoring to end of priority list
    // Get max priority for appending
    const maxPriorityResult = await pool.query(
      'SELECT MAX(priority_order) as max_priority FROM tasks WHERE user_id = $1 AND deleted = false',
      [req.user.id]
    );
    const nextPriority = (maxPriorityResult.rows[0]?.max_priority || 0) + 1;

    await pool.query(
      'UPDATE tasks SET deleted = false, priority_order = $1 WHERE id = $2 AND user_id = $3',
      [nextPriority, taskId, req.user.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Uncomplete task error:', error);
    res.status(500).json({ error: 'Failed to uncomplete task' });
  }
});

// ============================================================================
// SESSION AND COMPLETION ROUTES
// ============================================================================

// Helper function to validate and clean session state
async function cleanupSessionState(userId) {
  try {
    const sessionResult = await pool.query(
      'SELECT * FROM session_state WHERE user_id = $1',
      [userId]
    );
    
    if (sessionResult.rows.length === 0) {
      return null; // No session to clean
    }
    
    const session = sessionResult.rows[0];
    let needsCleanup = false;
    let cleanedCompletedIds = [];
    
    // Check if current_task_index is valid (exists and not deleted)
    const currentTaskResult = await pool.query(
      'SELECT id, deleted FROM tasks WHERE id = $1 AND user_id = $2',
      [session.current_task_index, userId]
    );
    
    if (currentTaskResult.rows.length === 0 || currentTaskResult.rows[0].deleted) {
      console.log(`⚠️  Session state cleanup: current_task_index ${session.current_task_index} is invalid or deleted`);
      needsCleanup = true;
    }
    
    // Check completed_task_ids array - remove any deleted or non-existent tasks
    if (session.completed_task_ids && session.completed_task_ids.length > 0) {
      for (const taskId of session.completed_task_ids) {
        const taskResult = await pool.query(
          'SELECT id, deleted FROM tasks WHERE id = $1 AND user_id = $2',
          [taskId, userId]
        );
        
        if (taskResult.rows.length > 0 && !taskResult.rows[0].deleted) {
          cleanedCompletedIds.push(taskId);
        } else {
          console.log(`⚠️  Session state cleanup: removing invalid/deleted task ${taskId} from completed_task_ids`);
          needsCleanup = true;
        }
      }
    }
    
    // If current task is invalid, clear the entire session
    if (currentTaskResult.rows.length === 0 || currentTaskResult.rows[0].deleted) {
      console.log(`🗑️  Clearing invalid session state for user ${userId}`);
      await pool.query('DELETE FROM session_state WHERE user_id = $1', [userId]);
      return null;
    }
    
    // If only completed_task_ids need cleaning, update them
    if (needsCleanup && cleanedCompletedIds.length !== session.completed_task_ids.length) {
      console.log(`🧹 Cleaning completed_task_ids for user ${userId}: ${session.completed_task_ids.length} -> ${cleanedCompletedIds.length}`);
      await pool.query(
        'UPDATE session_state SET completed_task_ids = $1 WHERE user_id = $2',
        [cleanedCompletedIds, userId]
      );
      session.completed_task_ids = cleanedCompletedIds;
    }
    
    return session;
  } catch (error) {
    console.error('Session state cleanup error:', error);
    return null;
  }
}

// Save session state
app.post('/api/sessions/saved-state', authenticateToken, async (req, res) => {
  try {
    const { sessionId, day, period, remainingTime, currentTaskIndex, taskStartTime, completedTaskIds } = req.body;
    
    // Validate current task exists and isn't deleted before saving
    const taskResult = await pool.query(
      'SELECT id, deleted FROM tasks WHERE id = $1 AND user_id = $2',
      [currentTaskIndex, req.user.id]
    );
    
    if (taskResult.rows.length === 0 || taskResult.rows[0].deleted) {
      console.log(`⚠️  Cannot save session: task ${currentTaskIndex} is invalid or deleted`);
      return res.status(400).json({ error: 'Cannot save session with invalid or deleted task' });
    }
    
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
    // Clean up session state first
    const cleanedSession = await cleanupSessionState(req.user.id);
    
    if (cleanedSession) {
      res.json({
        sessionId: `${cleanedSession.day}-${cleanedSession.period}`,
        day: cleanedSession.day,
        period: cleanedSession.period,
        remainingTime: cleanedSession.remaining_time,
        currentTaskIndex: cleanedSession.current_task_index,
        taskStartTime: cleanedSession.task_start_time,
        completedTaskIds: cleanedSession.completed_task_ids || [],
        savedAt: cleanedSession.saved_at
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
      `INSERT INTO tasks_completed (id, user_id, title, class, description, url, deadline_date, deadline_time, estimated_time, actual_time, completed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)`,
      [
        task.id,
        req.user.id,
        task.title,
        task.class,
        task.description,
        task.url,
        task.deadline_date,
        task.deadline_time,
        task.user_estimated_time || task.estimated_time,
        timeSpent
      ]
    );
    
    // Mark task as deleted instead of removing from database
    // This preserves the URL in the database so it won't be re-imported during sync
    await pool.query(
      'UPDATE tasks SET deleted = true, priority_order = NULL WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    
    // Update leaderboard and completion feed (async, don't await)
    updateLeaderboardOnCompletion(req.user.id).catch(err => console.error('Leaderboard update failed:', err));
    addToCompletionFeed(req.user.id, task.title, task.class).catch(err => console.error('Feed update failed:', err));
    
    res.json({ success: true });
  } catch (error) {
    console.error('Complete task error:', error);
    res.status(500).json({ error: 'Failed to complete task' });
  }
});

// Ignore/Delete a task (marks as deleted without moving to completed)
// Used when user wants to permanently ignore a task from the sidebar
app.post('/api/tasks/:taskId/ignore', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    
    const taskResult = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    
    if (taskResult.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    // Mark task as deleted and remove from priority order
    // This prevents it from showing in task list and from being re-imported during sync
    await pool.query(
      'UPDATE tasks SET deleted = true, priority_order = NULL WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    
    console.log(`✓ Task ${taskId} marked as ignored/deleted by user ${req.user.id}`);
    res.json({ success: true });
  } catch (error) {
    console.error('Ignore task error:', error);
    res.status(500).json({ error: 'Failed to ignore task' });
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
// HUB FEATURES - Completion Feed & Leaderboard
// ============================================================================

// Get recent completion feed (last 50 completions from opted-in users)
app.get('/api/completion-feed', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT cf.id, cf.user_name, cf.user_grade, cf.task_title, cf.task_class, cf.completed_at
       FROM completion_feed cf
       JOIN users u ON cf.user_id = u.id
       WHERE u.show_in_feed = true
       AND cf.completed_at > NOW() - INTERVAL '7 days'
       ORDER BY cf.completed_at DESC
       LIMIT 50`
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Get completion feed error:', error);
    res.status(500).json({ error: 'Failed to get completion feed' });
  }
});

// Get weekly leaderboard by grade
app.get('/api/leaderboard/:grade', authenticateToken, async (req, res) => {
  try {
    const { grade } = req.params;
    
    // Get current week start (Monday)
    const weekStart = await pool.query(
      `SELECT DATE_TRUNC('week', CURRENT_DATE)::date as week_start`
    );
    const currentWeekStart = weekStart.rows[0].week_start;
    
    // Get top 10 for this grade this week
    const result = await pool.query(
      `SELECT user_name, grade, tasks_completed, updated_at
       FROM weekly_leaderboard
       WHERE grade = $1 AND week_start = $2
       ORDER BY tasks_completed DESC, updated_at ASC
       LIMIT 10`,
      [grade, currentWeekStart]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Get leaderboard error:', error);
    res.status(500).json({ error: 'Failed to get leaderboard' });
  }
});

// Get user's current position in leaderboard
app.get('/api/leaderboard/position/:grade', authenticateToken, async (req, res) => {
  try {
    const { grade } = req.params;
    const userId = req.user.id;
    
    // Get current week start
    const weekStart = await pool.query(
      `SELECT DATE_TRUNC('week', CURRENT_DATE)::date as week_start`
    );
    const currentWeekStart = weekStart.rows[0].week_start;
    
    // Get user's position
    const result = await pool.query(
      `WITH ranked_users AS (
        SELECT user_id, user_name, tasks_completed,
               ROW_NUMBER() OVER (ORDER BY tasks_completed DESC, updated_at ASC) as position
        FROM weekly_leaderboard
        WHERE grade = $1 AND week_start = $2
      )
      SELECT position, user_name, tasks_completed
      FROM ranked_users
      WHERE user_id = $3`,
      [grade, currentWeekStart, userId]
    );
    
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.json({ position: null, tasks_completed: 0 });
    }
  } catch (error) {
    console.error('Get leaderboard position error:', error);
    res.status(500).json({ error: 'Failed to get position' });
  }
});

// Update user feed preference
app.put('/api/user/feed-preference', authenticateToken, async (req, res) => {
  try {
    const { showInFeed } = req.body;
    
    await pool.query(
      'UPDATE users SET show_in_feed = $1 WHERE id = $2',
      [showInFeed, req.user.id]
    );
    
    res.json({ success: true, showInFeed });
  } catch (error) {
    console.error('Update feed preference error:', error);
    res.status(500).json({ error: 'Failed to update preference' });
  }
});

// Helper function to update leaderboard when task is completed
async function updateLeaderboardOnCompletion(userId) {
  try {
    // Get user info
    const userResult = await pool.query(
      'SELECT name, grade, show_in_feed FROM users WHERE id = $1',
      [userId]
    );
    
    if (userResult.rows.length === 0) return;
    
    const user = userResult.rows[0];
    
    // Get current week start
    const weekStart = await pool.query(
      `SELECT DATE_TRUNC('week', CURRENT_DATE)::date as week_start`
    );
    const currentWeekStart = weekStart.rows[0].week_start;
    
    // Update or insert weekly leaderboard entry
    await pool.query(
      `INSERT INTO weekly_leaderboard (user_id, user_name, grade, tasks_completed, week_start, updated_at)
       VALUES ($1, $2, $3, 1, $4, CURRENT_TIMESTAMP)
       ON CONFLICT (user_id, week_start)
       DO UPDATE SET 
         tasks_completed = weekly_leaderboard.tasks_completed + 1,
         updated_at = CURRENT_TIMESTAMP`,
      [userId, user.name, user.grade, currentWeekStart]
    );
  } catch (error) {
    console.error('Update leaderboard error:', error);
  }
}

// Helper function to add to completion feed
async function addToCompletionFeed(userId, taskTitle, taskClass) {
  try {
    // Get user info
    const userResult = await pool.query(
      'SELECT name, grade, show_in_feed FROM users WHERE id = $1',
      [userId]
    );
    
    if (userResult.rows.length === 0 || !userResult.rows[0].show_in_feed) return;
    
    const user = userResult.rows[0];
    
    // Add to completion feed
    await pool.query(
      `INSERT INTO completion_feed (user_id, user_name, user_grade, task_title, task_class, completed_at)
       VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`,
      [userId, user.name, user.grade, taskTitle, taskClass]
    );
    
    // Keep only last 1000 entries to prevent table bloat
    await pool.query(
      `DELETE FROM completion_feed
       WHERE id IN (
         SELECT id FROM completion_feed
         ORDER BY completed_at DESC
         OFFSET 1000
       )`
    );
  } catch (error) {
    console.error('Add to completion feed error:', error);
  }
}

// Start server
app.listen(PORT, () => {
  console.log(`\n==============================================`);
  console.log(`  PlanAssist API v2.0 - REDESIGNED`);
  console.log(`  Server running on port ${PORT}`);
  console.log(`  Title/Segment System Active`);
  console.log(`  Advanced AI Estimation Enabled`);
  console.log(`==============================================\n`);
});
