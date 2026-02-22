// PlanAssist - COMPLETELY REDESIGNED Backend API
// server.js - New title/segment system with advanced AI estimation

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const Anthropic = require('@anthropic-ai/sdk');
const anthropicClient = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
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
// ADVANCED MULTI-TIER TIME ESTIMATION ALGORITHM
// ============================================================================

// Helper: Calculate linear regression for point-to-time correlation
const calculatePointTimeCorrelation = (dataPoints) => {
  // dataPoints: [{ points, time }, ...]
  if (dataPoints.length < 5) return null;
  
  const n = dataPoints.length;
  const sumPoints = dataPoints.reduce((sum, d) => sum + d.points, 0);
  const sumTime = dataPoints.reduce((sum, d) => sum + d.time, 0);
  const sumPointsTime = dataPoints.reduce((sum, d) => sum + (d.points * d.time), 0);
  const sumPointsSquared = dataPoints.reduce((sum, d) => sum + (d.points * d.points), 0);
  
  // Calculate slope (m) and intercept (b)
  const m = (n * sumPointsTime - sumPoints * sumTime) / (n * sumPointsSquared - sumPoints * sumPoints);
  const b = (sumTime - m * sumPoints) / n;
  
  // Calculate R-squared
  const meanTime = sumTime / n;
  const ssTotal = dataPoints.reduce((sum, d) => sum + Math.pow(d.time - meanTime, 2), 0);
  const ssResidual = dataPoints.reduce((sum, d) => {
    const predicted = m * d.points + b;
    return sum + Math.pow(d.time - predicted, 2);
  }, 0);
  const rSquared = 1 - (ssResidual / ssTotal);
  
  return { m, b, rSquared, n };
};

// Helper: Calculate user's speed factor
const calculateUserSpeedFactor = async (userId) => {
  try {
    const result = await pool.query(
      `SELECT 
         AVG(actual_time::float / NULLIF(estimated_time, 0)) as speed_factor
       FROM tasks_completed
       WHERE user_id = $1 AND estimated_time > 0
       HAVING COUNT(*) >= 5`,
      [userId]
    );
    
    if (result.rows[0] && result.rows[0].speed_factor) {
      const factor = parseFloat(result.rows[0].speed_factor);
      // Clamp between 0.5x and 2.0x to prevent extreme values
      return Math.max(0.5, Math.min(2.0, factor));
    }
  } catch (error) {
    console.error('Error calculating speed factor:', error.message);
  }
  
  return 1.0; // Default: no adjustment
};

// Helper: Auto-segment tasks over 60 minutes
const autoSegmentTask = (estimatedTime) => {
  if (estimatedTime <= 60) return null;
  
  // Calculate number of segments needed
  const segmentsNeeded = Math.ceil(estimatedTime / 60);
  
  // Divide time evenly
  const timePerSegment = Math.floor(estimatedTime / segmentsNeeded);
  const remainder = estimatedTime % segmentsNeeded;
  
  // Create segments
  const segments = [];
  for (let i = 1; i <= segmentsNeeded; i++) {
    segments.push({
      name: `Session ${i}`,
      estimatedTime: timePerSegment + (i <= remainder ? 1 : 0)
    });
  }
  
  return segments;
};

// Helper: Strip HTML tags and decode entities for AI consumption
const stripHtmlForAI = (html) => {
  if (!html) return '';
  return html
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<\/p>/gi, ' ')
    .replace(/<li>/gi, '• ')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s{2,}/g, ' ')
    .trim();
};

// Helper: Cached AI estimate - store in DB to avoid repeat calls
const getAIEstimate = async (assignmentId, title, description, pointsPossible) => {
  try {
    // Check cache first (stored in tasks table ai_estimate column if it exists,
    // otherwise just call the API each time - it's fast and cheap)
    const cleanDesc = stripHtmlForAI(description);
    const prompt = `You are estimating how long a high school assignment will take to complete.
Title: "${title}"
Description: "${cleanDesc}"
${pointsPossible ? `Points possible: ${pointsPossible}` : ''}

Consider the complexity, length requirements, and type of work described.
Reply with ONLY a single integer: the number of minutes this assignment will realistically take a typical student to complete.
Do not include any other text.`;

    const response = await anthropicClient.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 10,
      messages: [{ role: 'user', content: prompt }]
    });

    const rawText = response.content[0].text.trim();
    const minutes = parseInt(rawText);
    if (!isNaN(minutes) && minutes >= 5 && minutes <= 300) {
      console.log(`  ✓ AI estimate: ${minutes} min`);
      return minutes;
    }
    console.log(`  ✗ AI returned unparseable value: "${rawText}"`);
    return null;
  } catch (error) {
    console.error('  AI estimation error:', error.message);
    return null;
  }
};

// Main estimation function
const estimateTaskTime = async (task, userId) => {
  const {
    title,
    class: taskClass,
    url,
    assignmentId,
    courseId,
    pointsPossible,
    gradingType,
    description,
    isOSGCondensed,
    osgAssessments,
    osgQuizzes
  } = task;

  console.log(`\n=== ESTIMATING TIME FOR: "${title}" ===`);
  console.log(`Class: ${taskClass} | Points: ${pointsPossible || 'N/A'} | AssignmentId: ${assignmentId || 'N/A'}`);

  let estimate = null;
  let confidence = 'BASELINE';
  let source = 'Default';

  // =========================================================================
  // STEP 1: Homeroom → always 0
  // =========================================================================
  if (taskClass && (taskClass.includes('Homeroom') || taskClass.includes('homeroom'))) {
    console.log('✓ STEP 1: Homeroom → 0 min');
    return 0;
  }

  // =========================================================================
  // STEP 2: OSG Accelerate condensed task → formula
  // =========================================================================
  if (isOSGCondensed && (osgAssessments !== undefined || osgQuizzes !== undefined)) {
    const assessments = osgAssessments || 0;
    const quizzes = osgQuizzes || 0;
    estimate = (assessments * 30) + (quizzes * 5) + 15;
    console.log(`✓ STEP 2: OSG formula → ${estimate} min (${assessments}×30 + ${quizzes}×5 + 15)`);
    return estimate;
  }

  // =========================================================================
  // STEP 3: Same assignment completed by ANY user ≥6 times → correlation
  // =========================================================================
  if (!estimate && assignmentId) {
    console.log('STEP 3: Checking cross-user assignment history...');
    try {
      const exactResult = await pool.query(
        `SELECT tc.actual_time, t.points_possible
         FROM tasks_completed tc
         LEFT JOIN tasks t ON t.assignment_id = $1 AND t.user_id = tc.user_id
         WHERE tc.url IN (
           SELECT url FROM tasks WHERE assignment_id = $1 LIMIT 1
         )
         AND tc.actual_time > 0`,
        [assignmentId]
      );

      if (exactResult.rows.length >= 6) {
        if (pointsPossible && pointsPossible > 0) {
          // Try points correlation first
          const dataPoints = exactResult.rows
            .filter(r => r.points_possible > 0)
            .map(r => ({ points: parseFloat(r.points_possible), time: parseInt(r.actual_time) }));

          if (dataPoints.length >= 6) {
            const correlation = calculatePointTimeCorrelation(dataPoints);
            if (correlation && correlation.rSquared > 0.5) {
              const speedFactor = await calculateUserSpeedFactor(userId);
              estimate = Math.round((correlation.m * pointsPossible + correlation.b) * speedFactor);
              confidence = 'VERY_HIGH';
              source = `Same assignment, ${exactResult.rows.length} completions, points correlation (R²=${correlation.rSquared.toFixed(2)})`;
              console.log(`✓ STEP 3 (correlation): ${estimate} min`);
            }
          }
        }

        // Fall back to simple average if correlation didn't fire
        if (!estimate) {
          const times = exactResult.rows.map(r => parseInt(r.actual_time)).sort((a, b) => a - b);
          // Trimmed mean: drop top and bottom if we have enough
          const trimmed = times.length >= 8 ? times.slice(1, -1) : times;
          const avg = Math.round(trimmed.reduce((s, t) => s + t, 0) / trimmed.length);
          const speedFactor = await calculateUserSpeedFactor(userId);
          estimate = Math.round(avg * speedFactor);
          confidence = 'VERY_HIGH';
          source = `Same assignment, ${exactResult.rows.length} completions, avg ${avg} min`;
          console.log(`✓ STEP 3 (average): ${estimate} min`);
        }
      } else {
        console.log(`✗ STEP 3: Only ${exactResult.rows.length} completions (need 6+)`);
      }
    } catch (error) {
      console.error('STEP 3 error:', error.message);
    }
  }

  // =========================================================================
  // STEP 4: Enrichment / NEST → 10 min
  // =========================================================================
  if (!estimate && taskClass && (
    taskClass.includes('Enrichment') || taskClass.includes('enrichment') || taskClass.includes('NEST')
  )) {
    console.log('✓ STEP 4: Enrichment/NEST → 10 min');
    return 10;
  }

  // =========================================================================
  // STEP 5: Same course (course_id OR course_name), ≥14 completions → correlation
  // =========================================================================
  if (!estimate && pointsPossible && pointsPossible > 0) {
    console.log('STEP 5: Checking cross-user course correlation...');
    try {
      // Match on course_id if available, otherwise course name
      let courseQuery, courseParams;
      if (courseId) {
        courseQuery = `SELECT tc.actual_time, t.points_possible
                        FROM tasks_completed tc
                        JOIN tasks t ON tc.url = t.url
                        WHERE t.course_id = $1
                          AND t.points_possible > 0
                          AND tc.actual_time > 0`;
        courseParams = [courseId];
      } else {
        courseQuery = `SELECT tc.actual_time, t.points_possible
                        FROM tasks_completed tc
                        JOIN tasks t ON tc.url = t.url
                        WHERE tc.class = $1
                          AND t.points_possible > 0
                          AND tc.actual_time > 0`;
        courseParams = [taskClass];
      }

      const courseData = await pool.query(courseQuery, courseParams);

      if (courseData.rows.length >= 14) {
        const dataPoints = courseData.rows.map(r => ({
          points: parseFloat(r.points_possible),
          time: parseInt(r.actual_time)
        }));

        const correlation = calculatePointTimeCorrelation(dataPoints);
        if (correlation && correlation.rSquared > 0.5) {
          const speedFactor = await calculateUserSpeedFactor(userId);
          estimate = Math.round((correlation.m * pointsPossible + correlation.b) * speedFactor);
          confidence = 'HIGH';
          source = `Course correlation (R²=${correlation.rSquared.toFixed(2)}, n=${courseData.rows.length})`;
          console.log(`✓ STEP 5: ${estimate} min (${source})`);
        } else {
          console.log(`✗ STEP 5: Weak correlation (R²=${correlation?.rSquared.toFixed(2) || 'N/A'})`);
        }
      } else {
        console.log(`✗ STEP 5: Only ${courseData.rows.length} course completions (need 14+)`);
      }
    } catch (error) {
      console.error('STEP 5 error:', error.message);
    }
  }

  // =========================================================================
  // STEP 6: AI description analysis (Haiku)
  // =========================================================================
  if (!estimate && description) {
    const cleanDesc = stripHtmlForAI(description);
    if (cleanDesc.length >= 20 && cleanDesc.length <= 1200) {
      console.log(`STEP 6: AI description analysis (${cleanDesc.length} chars)...`);
      try {
        const aiEstimate = await getAIEstimate(assignmentId, title, cleanDesc, pointsPossible);
        if (aiEstimate !== null) {
          estimate = aiEstimate;
          confidence = 'MEDIUM';
          source = 'AI description analysis';
          console.log(`✓ STEP 6: ${estimate} min`);
        } else {
          console.log('✗ STEP 6: AI returned no usable estimate');
        }
      } catch (error) {
        console.error('STEP 6 error:', error.message);
      }
    } else {
      console.log(`✗ STEP 6: Description length ${cleanDesc.length} chars (need 20-1200)`);
    }
  }

  // =========================================================================
  // STEP 7: Keyword matching — check ALL keywords, average their estimates
  // =========================================================================
  if (!estimate) {
    console.log('STEP 7: Keyword analysis...');
    const keywordRules = {
      'Project':      { base: 90,  pointsMultiplier: 1.2 },
      'Essay':        { base: 60,  pointsMultiplier: 1.0 },
      'Exam':         { base: 60,  pointsMultiplier: 0.8 },
      'Test':         { base: 45,  pointsMultiplier: 0.8 },
      'Lab':          { base: 75,  pointsMultiplier: 1.1 },
      'Presentation': { base: 60,  pointsMultiplier: 1.0 },
      'Discussion':   { base: 20,  pointsMultiplier: 0.5 },
      'Quiz':         { base: 15,  pointsMultiplier: 0.6 },
      'Assessment':   { base: 30,  pointsMultiplier: 0.7 },
      'Worksheet':    { base: 25,  pointsMultiplier: 0.7 },
      'Reading':      { base: 30,  pointsMultiplier: 0.6 },
      'Homework':     { base: 30,  pointsMultiplier: 0.8 },
      'Share':        { base: 5,   pointsMultiplier: 0.3 },
      'Reflection':   { base: 15,  pointsMultiplier: 0.5 },
      'Response':     { base: 10,  pointsMultiplier: 0.4 }
    };

    const matchedEstimates = [];
    const titleUpper = title.toUpperCase();

    for (const [keyword, rule] of Object.entries(keywordRules)) {
      if (titleUpper.includes(keyword.toUpperCase())) {
        const kEstimate = pointsPossible && pointsPossible > 0
          ? Math.round(rule.base + (pointsPossible * rule.pointsMultiplier))
          : rule.base;
        matchedEstimates.push(kEstimate);
        console.log(`  Keyword "${keyword}": ${kEstimate} min`);
      }
    }

    if (matchedEstimates.length > 0) {
      estimate = Math.round(matchedEstimates.reduce((s, v) => s + v, 0) / matchedEstimates.length);
      confidence = 'LOW';
      source = `Keyword match (${matchedEstimates.length} keywords, averaged)`;
      console.log(`✓ STEP 7: ${estimate} min (${source})`);
    } else {
      console.log('✗ STEP 7: No keywords matched');
    }
  }

  // =========================================================================
  // STEP 8: Points-based fallback
  // =========================================================================
  if (!estimate && pointsPossible && pointsPossible > 0) {
    console.log('STEP 8: Points-based fallback...');
    if      (pointsPossible <= 5)   estimate = 15;
    else if (pointsPossible <= 20)  estimate = 25;
    else if (pointsPossible <= 50)  estimate = 35;
    else if (pointsPossible <= 100) estimate = 50;
    else if (pointsPossible <= 200) estimate = 70;
    else                            estimate = 90;
    confidence = 'LOW';
    source = `Points-based (${pointsPossible} pts)`;
    console.log(`✓ STEP 8: ${estimate} min (${source})`);
  }

  // =========================================================================
  // STEP 9: Final fallback → 20 min
  // =========================================================================
  if (!estimate) {
    estimate = 20;
    confidence = 'BASELINE';
    source = 'Default fallback';
    console.log('✓ STEP 9: Default → 20 min');
  }

  // Clamp to sane range
  estimate = Math.max(5, Math.min(300, estimate));

  console.log(`\n=== FINAL ESTIMATE: ${estimate} min | ${confidence} | ${source} ===`);
  return estimate;
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
      'SELECT grade, canvas_api_token, canvas_api_token_iv, present_periods, calendar_today_centered, calendar_show_homeroom, calendar_show_completed FROM users WHERE id = $1',
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
      schedule,
      calendarTodayCentered: user.calendar_today_centered ?? false,
      calendarShowHomeroom: user.calendar_show_homeroom ?? false,
      calendarShowCompleted: user.calendar_show_completed ?? true
    });
  } catch (error) {
    console.error('Get account setup error:', error);
    res.status(500).json({ error: 'Failed to get account setup' });
  }
});

// Save account setup
app.post('/api/account/setup', authenticateToken, async (req, res) => {
  try {
    const { grade, canvasApiToken, presentPeriods, schedule, calendarTodayCentered, calendarShowHomeroom, calendarShowCompleted } = req.body;

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
      `UPDATE users SET grade = $1, canvas_api_token = $2, canvas_api_token_iv = $3,
        present_periods = $4, is_new_user = false,
        calendar_today_centered = $5, calendar_show_homeroom = $6, calendar_show_completed = $7
       WHERE id = $8`,
      [grade, encryptedToken, iv, presentPeriods,
       calendarTodayCentered ?? false,
       calendarShowHomeroom ?? false,
       calendarShowCompleted ?? true,
       req.user.id]
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
// NEW CANVAS API SYNC ENDPOINT
// ============================================================================

// Sync assignments from Canvas API (replaces /calendar/fetch)
app.post('/api/canvas/sync', authenticateToken, async (req, res) => {
  try {
    console.log('\n=== CANVAS API SYNC START ===');
    
    // Get user's encrypted Canvas API token
    const userResult = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (!userResult.rows[0] || !userResult.rows[0].canvas_api_token) {
      return res.status(400).json({ error: 'No Canvas API token found. Please add your token in Settings.' });
    }
    
    // Decrypt the Canvas API token
    const encryptedParts = userResult.rows[0].canvas_api_token.split(':');
    if (encryptedParts.length !== 2) {
      return res.status(500).json({ error: 'Invalid token format in database' });
    }
    
    const canvasToken = decryptToken(
      encryptedParts[0],
      userResult.rows[0].canvas_api_token_iv,
      encryptedParts[1]
    );
    
    if (!canvasToken) {
      return res.status(500).json({ error: 'Failed to decrypt Canvas API token' });
    }
    
    console.log('✓ Canvas API token decrypted successfully');
    
    // Canvas API base URL
    const CANVAS_API_BASE = 'https://canvas.oneschoolglobal.com/api/v1';
    const headers = {
      'Authorization': `Bearer ${canvasToken}`,
      'Accept': 'application/json'
    };
    
    // Step 1: Fetch all active courses for the user
    console.log('\n📚 Fetching active courses...');
    let coursesResponse;
    try {
      coursesResponse = await axios.get(
        `${CANVAS_API_BASE}/courses?enrollment_state=active&include[]=total_scores&include[]=current_grading_period_scores&per_page=100`,
        { headers, timeout: 15000 }
      );
    } catch (error) {
      console.error('❌ Failed to fetch courses:', error.message);
      if (error.response?.status === 401) {
        return res.status(401).json({ error: 'Canvas API token is invalid or expired. Please update your token in Settings.' });
      }
      return res.status(500).json({ error: 'Failed to fetch courses from Canvas', details: error.message });
    }
    
    const courses = coursesResponse.data;
    console.log(`✓ Found ${courses.length} active courses`);
    
    // Step 2: Sync course data to database
    console.log('\n💾 Syncing course data to database...');
    for (const course of courses) {
      // Get enrollment data for grades - Canvas API returns enrollments array with total_scores
      const enrollment = course.enrollments?.[0] || {};
      
      // Canvas returns computed_current_score OR grades.current_score depending on API version
      const currentScore = enrollment.computed_current_score ?? enrollment.grades?.current_score ?? null;
      const currentGrade = enrollment.computed_current_grade ?? enrollment.grades?.current_grade ?? null;
      const finalScore = enrollment.computed_final_score ?? enrollment.grades?.final_score ?? null;
      const finalGrade = enrollment.computed_final_grade ?? enrollment.grades?.final_grade ?? null;
      
      console.log(`  Course: ${course.name} | Score: ${currentScore} | Grade: ${currentGrade}`);
      
      await pool.query(
        `INSERT INTO courses (user_id, course_id, name, course_code, current_score, current_grade, final_score, final_grade, enrollment_id, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
         ON CONFLICT (user_id, course_id)
         DO UPDATE SET 
           name = EXCLUDED.name,
           course_code = EXCLUDED.course_code,
           current_score = EXCLUDED.current_score,
           current_grade = EXCLUDED.current_grade,
           final_score = EXCLUDED.final_score,
           final_grade = EXCLUDED.final_grade,
           updated_at = CURRENT_TIMESTAMP`,
        [
          req.user.id,
          course.id,
          course.name,
          course.course_code || null,
          currentScore,
          currentGrade,
          finalScore,
          finalGrade,
          enrollment.id || null
        ]
      );
    }
    console.log(`✓ Synced ${courses.length} courses to database`);
    
    // Step 3: Fetch assignment groups for grade weight calculations
    console.log('\n⚖️  Fetching assignment groups...');
    for (const course of courses) {
      try {
        const groupsResponse = await axios.get(
          `${CANVAS_API_BASE}/courses/${course.id}/assignment_groups`,
          { headers, timeout: 10000 }
        );
        
        for (const group of groupsResponse.data) {
          await pool.query(
            `INSERT INTO assignment_groups (user_id, course_id, group_id, name, weight, updated_at)
             VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
             ON CONFLICT (user_id, course_id, group_id)
             DO UPDATE SET 
               name = EXCLUDED.name,
               weight = EXCLUDED.weight,
               updated_at = CURRENT_TIMESTAMP`,
            [req.user.id, course.id, group.id, group.name, group.group_weight || null]
          );
        }
        console.log(`  ✓ Course: ${course.name} - ${groupsResponse.data.length} assignment groups`);
      } catch (error) {
        console.error(`  ⚠️  Failed to fetch assignment groups for ${course.name}:`, error.message);
      }
    }
    

    
    // Step 4: Fetch assignments from all courses
    console.log('\n📋 Fetching assignments...');
    const allAssignments = [];
    const today = new Date();
    const oneMonthFromNow = new Date(today.getTime() + 30 * 24 * 60 * 60 * 1000);
    
    for (const course of courses) {
      try {
        const assignmentsResponse = await axios.get(
          `${CANVAS_API_BASE}/courses/${course.id}/assignments?include[]=submission&per_page=100`,
          { headers, timeout: 15000 }
        );
        
        for (const assignment of assignmentsResponse.data) {
          // Only include assignments with due dates
          if (!assignment.due_at) continue;
          
          const dueDate = new Date(assignment.due_at);
          
          // Only include assignments within the next month
          if (dueDate >= today && dueDate <= oneMonthFromNow) {
            allAssignments.push({
              ...assignment,
              course_name: course.name,
              course_id: course.id
            });
          }
        }
        
        console.log(`  ✓ Course: ${course.name} - ${assignmentsResponse.data.length} total assignments`);
      } catch (error) {
        console.error(`  ⚠️  Failed to fetch assignments for ${course.name}:`, error.message);
      }
    }
    
    console.log(`✓ Found ${allAssignments.length} assignments within the next month`);
    
    // Step 5: Format assignments for database with time estimation
    // MIGRATION: Update any existing OSG condensed tasks with old URL formats to /modules?week=YYYY-MM-DD
    // Old format 1: /assignments#YYYY-MM-DD  (pre-fix format with date fragment)
    // Old format 2: /modules (no week param - from previous migration, missing date)
    const oldOsgRows = await pool.query(
      `SELECT id, url, deadline_date FROM tasks
       WHERE user_id = $1
         AND deleted = false
         AND title LIKE 'OSG Accelerate%'
         AND (url LIKE '%assignments#%' OR (url LIKE '%/modules' AND url NOT LIKE '%?week=%'))`,
      [req.user.id]
    );
    for (const row of oldOsgRows.rows) {
      const courseMatch = row.url.match(/\/courses\/(\d+)\//);
      if (courseMatch && row.deadline_date) {
        const dateStr = typeof row.deadline_date === 'string'
          ? row.deadline_date.split('T')[0]
          : new Date(row.deadline_date).toISOString().split('T')[0];
        const newUrl = `https://canvas.oneschoolglobal.com/courses/${courseMatch[1]}/modules?week=${dateStr}`;
        await pool.query('UPDATE tasks SET url = $1 WHERE id = $2', [newUrl, row.id]);
        console.log(`  ✓ Migrated OSG URL: ${row.url} → ${newUrl}`);
      }
    }

    console.log('\n🔄 Formatting assignments and estimating times...');
    const tasks = [];
    const osgAccelerateTasks = []; // Collect OSGAccelerate tasks for condensing
    
    for (const assignment of allAssignments) {
      const dueDate = new Date(assignment.due_at);
      
      // Extract date and time in UTC
      const deadlineDate = dueDate.toISOString().split('T')[0]; // YYYY-MM-DD
      const timeString = dueDate.toISOString().split('T')[1]; // HH:MM:SS.sssZ
      const deadlineTime = timeString.split('.')[0]; // HH:MM:SS (remove milliseconds and Z)
      
      // Get submission data
      const submission = assignment.submission || {};
      const isSubmitted = submission.workflow_state === 'submitted' || submission.workflow_state === 'graded';
      

      
      // Check if this is an OSGAccelerate task that should be condensed
      const isOSGCourse = assignment.course_name.includes('OSGAccelerate') || 
                          assignment.course_name.includes('OSG Accelerate');
      if (isOSGCourse) {
        osgAccelerateTasks.push({
          assignment,
          dueDate,
          deadlineDate,
          deadlineTime,
          submission,
          isSubmitted
        });
        continue; // Don't process individually, we'll condense later
      }
      
      // Create base task object for estimation
      const taskForEstimation = {
        title: assignment.name,
        class: assignment.course_name,
        url: assignment.html_url,
        assignmentId: assignment.id,
        pointsPossible: assignment.points_possible || null,
        assignmentGroupId: assignment.assignment_group_id || null,
        gradingType: assignment.grading_type || 'points',
        description: assignment.description || ''
      };
      
      // Estimate time using new intelligent algorithm
      const estimatedTime = await estimateTaskTime(taskForEstimation, req.user.id);
      
      tasks.push({
          title: assignment.name,
          segment: null,
          class: assignment.course_name,
          description: assignment.description || '',
          url: assignment.html_url,
          deadlineDate: deadlineDate,
          deadlineTime: deadlineTime,
          estimatedTime: estimatedTime,
          // Canvas API fields
          courseId: assignment.course_id,
          assignmentId: assignment.id,
          pointsPossible: assignment.points_possible || null,
          assignmentGroupId: assignment.assignment_group_id || null,
          currentScore: submission.score || null,
          currentGrade: submission.grade || null,
          gradingType: assignment.grading_type || 'points',
          unlockAt: assignment.unlock_at || null,
          lockAt: assignment.lock_at || null,
          submittedAt: submission.submitted_at || null,
          isMissing: submission.missing || false,
          isLate: submission.late || false,
          completed: isSubmitted
        });
    }
    
    // Process OSGAccelerate tasks - condense by deadline date
    console.log('\n🎓 Processing OSGAccelerate tasks for condensing...');
    const osgDayGroups = {};
    
    for (const osgTask of osgAccelerateTasks) {
      const key = osgTask.deadlineDate; // Group by due date only
      if (!osgDayGroups[key]) {
        osgDayGroups[key] = [];
      }
      osgDayGroups[key].push(osgTask);
    }
    
    // Create condensed tasks for each day group
    for (const [deadlineDate, groupTasks] of Object.entries(osgDayGroups)) {
      if (groupTasks.length === 0) continue;
      
      const firstTask = groupTasks[0];
      
      // Count by type: Assessment = contains "Assessment", Quiz = contains "Quiz"
      let assessmentCount = 0;
      let quizCount = 0;
      
      for (const task of groupTasks) {
        const title = task.assignment.name;
        if (title.includes('Assessment')) assessmentCount++;
        if (title.includes('Quiz')) quizCount++;
      }
      
      // Build title: "OSG Accelerate (2 Assessments) (7 Quizzes)"
      const titleParts = [];
      if (assessmentCount > 0) titleParts.push(`${assessmentCount} Assessment${assessmentCount !== 1 ? 's' : ''}`);
      if (quizCount > 0) titleParts.push(`${quizCount} ${quizCount !== 1 ? 'Quizzes' : 'Quiz'}`);
      const condensedTitle = `OSG Accelerate (${titleParts.join(') (')})`;
      
      // Time formula: (Assessments * 30) + (Quizzes * 5) + 15
      const condensedTime = (assessmentCount * 30) + (quizCount * 5) + 15;
      
      // Check if all tasks in group are submitted
      const allSubmitted = groupTasks.every(t => t.isSubmitted);
      
      // URL: OSG Accelerate course assignments page, unique per day via query param
      const osgCourseId = firstTask.assignment.course_id;
      const condensedUrl = `https://canvas.oneschoolglobal.com/courses/${osgCourseId}/modules?week=${deadlineDate}`;
      
      console.log(`  ✓ Condensed OSG ${deadlineDate}: ${groupTasks.length} tasks (${assessmentCount} assessments, ${quizCount} quizzes) → ${condensedTime} min`);
      
      const condensedTaskBase = {
        title: condensedTitle,
        class: firstTask.assignment.course_name,
        description: `OSG Accelerate condensed tasks for ${deadlineDate} | Assignment IDs: ${groupTasks.map(t => t.assignment.id).join(',')}`,
        url: condensedUrl,
        deadlineDate: firstTask.deadlineDate,
        deadlineTime: firstTask.deadlineTime,
        courseId: firstTask.assignment.course_id,
        assignmentId: null,
        pointsPossible: null,
        assignmentGroupId: firstTask.assignment.assignment_group_id,
        currentScore: null,
        currentGrade: null,
        gradingType: 'points',
        unlockAt: null,
        lockAt: null,
        submittedAt: allSubmitted ? new Date().toISOString() : null,
        isMissing: false,
        isLate: false,
        completed: allSubmitted
      };
      
      tasks.push({ ...condensedTaskBase, segment: null, estimatedTime: condensedTime });
    }
    
    console.log(`✓ Formatted ${tasks.length} tasks for database (with auto-segmentation and OSG condensing)`);
    console.log(`  - Regular tasks: ${tasks.length - Object.keys(osgDayGroups).length}`);
    console.log(`  - Condensed OSG days: ${Object.keys(osgDayGroups).length}`);
    console.log('\n=== CANVAS API SYNC COMPLETE ===\n');
    
    res.json({ 
      tasks,
      stats: {
        courses: courses.length,
        assignments: tasks.length
      }
    });
    
  } catch (error) {
    console.error('❌ Canvas API sync error:', error);
    console.error('Stack:', error.stack);
    res.status(500).json({ 
      error: 'Failed to sync with Canvas',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// ============================================================================
// COURSES & GRADES ROUTES (for Marks tab)
// ============================================================================

// Get all courses with current grades
app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM courses 
       WHERE user_id = $1
       ORDER BY name ASC`,
      [req.user.id]
    );
    res.json(result.rows || []);
  } catch (error) {
    console.error('Get courses error:', error);
    res.status(500).json({ error: 'Failed to get courses' });
  }
});

// Get assignment groups for a specific course
app.get('/api/courses/:courseId/assignment-groups', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    
    const result = await pool.query(
      `SELECT * FROM assignment_groups 
       WHERE user_id = $1 AND course_id = $2
       ORDER BY name ASC`,
      [req.user.id, courseId]
    );
    res.json(result.rows || []);
  } catch (error) {
    console.error('Get assignment groups error:', error);
    res.status(500).json({ error: 'Failed to get assignment groups' });
  }
});

// Get global average score for a course (across all PlanAssist users)
app.get('/api/courses/:courseId/average', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    
    const result = await pool.query(
      `SELECT AVG(current_score) as avg_score, COUNT(DISTINCT user_id) as student_count
       FROM courses
       WHERE course_id = $1 AND current_score IS NOT NULL`,
      [courseId]
    );
    
    res.json({
      averageScore: result.rows[0]?.avg_score ? parseFloat(result.rows[0].avg_score) : null,
      studentCount: parseInt(result.rows[0]?.student_count) || 0
    });
  } catch (error) {
    console.error('Get course average error:', error);
    res.status(500).json({ error: 'Failed to get course average' });
  }
});

// ============================================================================
// TASK MANAGEMENT ROUTES
// ============================================================================

// Get tasks (all incomplete tasks)
// Calendar endpoint - returns ALL non-deleted tasks (including completed)
// plus tasks_completed entries, merged for the calendar view
app.get('/api/tasks/calendar', authenticateToken, async (req, res) => {
  try {
    // Active + completed tasks still in tasks table (deleted=false)
    const activeResult = await pool.query(
      `SELECT id, title, segment, class, url, description,
              deadline_date, deadline_time, priority_order,
              completed, submitted_at, is_missing, is_late,
              points_possible, course_id, assignment_id
       FROM tasks
       WHERE user_id = $1 AND deleted = false
       ORDER BY deadline_date ASC, deadline_time ASC NULLS LAST`,
      [req.user.id]
    );

    // Tasks completed via sessions (hard-deleted from tasks, moved to tasks_completed)
    // Only fetch within a reasonable window (30 days back, 30 days forward)
    const completedResult = await pool.query(
      `SELECT id, title, NULL as segment, class, url, NULL as description,
              deadline::date as deadline_date,
              deadline::time as deadline_time,
              NULL as priority_order,
              true as completed, completed_at as submitted_at,
              false as is_missing, false as is_late,
              NULL as points_possible, NULL as course_id, NULL as assignment_id
       FROM tasks_completed
       WHERE user_id = $1
         AND deadline >= NOW() - INTERVAL '30 days'
         AND deadline <= NOW() + INTERVAL '30 days'`,
      [req.user.id]
    );

    // Merge: avoid duplicates (tasks_completed entries whose url matches active tasks)
    const activeUrls = new Set(activeResult.rows.map(t => t.url));
    const dedupedCompleted = completedResult.rows.filter(t => !activeUrls.has(t.url));

    const allTasks = [...activeResult.rows, ...dedupedCompleted];
    res.json(allTasks);
  } catch (error) {
    console.error('Calendar tasks error:', error);
    res.json([]);
  }
});

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

    console.log(`\n=== SYNC OPERATION: Processing ${tasks.length} tasks from Canvas API ===`);

    // CRITICAL: Sort tasks by deadline before assigning priorities
    // This ensures priority_order follows chronological deadline order
    const sortedTasks = [...tasks].sort((a, b) => {
      const dateA = new Date(`${a.deadlineDate}T${a.deadlineTime || '23:59:59'}Z`);
      const dateB = new Date(`${b.deadlineDate}T${b.deadlineTime || '23:59:59'}Z`);
      return dateA - dateB;
    });
    
    console.log('✓ Tasks sorted by deadline (earliest first)');

    // Track what we do for logging
    let updatedCount = 0;
    let newCount = 0;
    const insertedTasks = [];

    for (const incomingTask of sortedTasks) {
      // Check if this task already exists (match by assignment_id first, then URL)
      let existingTasksResult;
      
      if (incomingTask.assignmentId) {
        // Try matching by Canvas assignment_id first (most reliable)
        existingTasksResult = await pool.query(
          'SELECT * FROM tasks WHERE user_id = $1 AND assignment_id = $2',
          [req.user.id, incomingTask.assignmentId]
        );
        
        // If no match by assignment_id, fall back to URL matching
        if (existingTasksResult.rows.length === 0) {
          existingTasksResult = await pool.query(
            'SELECT * FROM tasks WHERE user_id = $1 AND url = $2',
            [req.user.id, incomingTask.url]
          );
        }
      } else {
        // No assignment_id (e.g. OSG condensed tasks) - match by title+deadline_date first,
        // which is more reliable than URL since URL format can change
        if (incomingTask.title && incomingTask.deadlineDate) {
          existingTasksResult = await pool.query(
            `SELECT * FROM tasks WHERE user_id = $1 AND title = $2 AND deadline_date = $3
             ORDER BY id ASC`,
            [req.user.id, incomingTask.title, incomingTask.deadlineDate]
          );
          if (existingTasksResult.rows.length > 0) {
            console.log(`[OSG MATCH] Found by title+date: "${incomingTask.title}" on ${incomingTask.deadlineDate}`);
            // Update URL to current format while we're here
            const existRow = existingTasksResult.rows[0];
            if (existRow.url !== incomingTask.url) {
              await pool.query('UPDATE tasks SET url = $1 WHERE id = $2', [incomingTask.url, existRow.id]);
              existingTasksResult.rows[0].url = incomingTask.url;
            }
            // If multiple rows found (old duplicates), soft-delete extras
            if (existingTasksResult.rows.length > 1) {
              const extraIds = existingTasksResult.rows.slice(1).map(r => r.id);
              await pool.query(
                `UPDATE tasks SET deleted = true, priority_order = NULL WHERE id = ANY($1)`,
                [extraIds]
              );
              console.log(`[OSG CLEANUP] Soft-deleted ${extraIds.length} duplicate(s): ids ${extraIds.join(',')}`);
              existingTasksResult = { rows: [existingTasksResult.rows[0]] };
            }
          } else {
            // Fall back to URL
            existingTasksResult = await pool.query(
              'SELECT * FROM tasks WHERE user_id = $1 AND url = $2',
              [req.user.id, incomingTask.url]
            );
          }
        } else {
          existingTasksResult = await pool.query(
            'SELECT * FROM tasks WHERE user_id = $1 AND url = $2',
            [req.user.id, incomingTask.url]
          );
        }
      }

      if (existingTasksResult.rows.length > 0) {
        // Task EXISTS - Update, but only overwrite Canvas fields if they're actually provided
        console.log(`\n[UPDATE] Found ${existingTasksResult.rows.length} existing task(s) with URL: ${incomingTask.url}`);
        
        // Detect if this is a Canvas sync (has canvas fields) vs a plan reorder (no canvas fields)
        const hasCanvasData = incomingTask.courseId !== undefined || incomingTask.assignmentId !== undefined;
        
        for (const existingTask of existingTasksResult.rows) {
          if (hasCanvasData) {
            // Full Canvas sync update — overwrite canvas fields with fresh data
            // For split segments, skip canvas field update entirely to avoid
            // duplicate assignment_id constraint violations across multiple segments
            if (existingTask.segment) {
              // This is a user-created segment - only update non-canvas display fields
              await pool.query(
                `UPDATE tasks SET 
                  title = $1,
                  class = $2,
                  url = $3,
                  deadline_date = $4,
                  deadline_time = $5,
                  points_possible = $6,
                  current_score = $7,
                  current_grade = $8,
                  submitted_at = $9,
                  is_missing = $10,
                  is_late = $11
                 WHERE id = $12 AND user_id = $13`,
                [
                  incomingTask.title,
                  incomingTask.class,
                  incomingTask.url,
                  incomingTask.deadlineDate,
                  incomingTask.deadlineTime,
                  incomingTask.pointsPossible ?? null,
                  incomingTask.currentScore ?? null,
                  incomingTask.currentGrade ?? null,
                  incomingTask.submittedAt ?? null,
                  incomingTask.isMissing ?? false,
                  incomingTask.isLate ?? false,
                  existingTask.id,
                  req.user.id
                ]
              );
            } else {
              // Non-segment task: full canvas field update
              await pool.query(
                `UPDATE tasks SET 
                  title = $1,
                  description = $2,
                  estimated_time = $3,
                  completed = $4,
                  class = $5,
                  url = $6,
                  deadline_date = $7,
                  deadline_time = $8,
                  course_id = $9,
                  assignment_id = $10,
                  points_possible = $11,
                  assignment_group_id = $12,
                  current_score = $13,
                  current_grade = $14,
                  grading_type = $15,
                  unlock_at = $16,
                  lock_at = $17,
                  submitted_at = $18,
                  is_missing = $19,
                  is_late = $20
                 WHERE id = $21 AND user_id = $22`,
                [
                  incomingTask.title,
                  incomingTask.description || '',
                  incomingTask.estimatedTime,
                  incomingTask.completed ?? false,
                  incomingTask.class,
                  incomingTask.url,
                  incomingTask.deadlineDate,
                  incomingTask.deadlineTime,
                  incomingTask.courseId ?? null,
                  incomingTask.assignmentId ?? null,
                  incomingTask.pointsPossible ?? null,
                  incomingTask.assignmentGroupId ?? null,
                  incomingTask.currentScore ?? null,
                  incomingTask.currentGrade ?? null,
                  incomingTask.gradingType || 'points',
                  incomingTask.unlockAt ?? null,
                  incomingTask.lockAt ?? null,
                  incomingTask.submittedAt ?? null,
                  incomingTask.isMissing ?? false,
                  incomingTask.isLate ?? false,
                  existingTask.id,
                  req.user.id
                ]
              );
            }
          } else {
            // Plan reorder / save — only update non-canvas fields, preserve all canvas data
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
                incomingTask.completed ?? false,
                incomingTask.class,
                incomingTask.url,
                incomingTask.deadlineDate,
                incomingTask.deadlineTime,
                existingTask.id,
                req.user.id
              ]
            );
          }
          
          console.log(`  ✓ Updated task ID ${existingTask.id}: "${existingTask.title}"`);
          console.log(`    Canvas data: courseId=${incomingTask.courseId}, assignmentId=${incomingTask.assignmentId}, points=${incomingTask.pointsPossible} (hasCanvasData=${hasCanvasData})`);
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
        // URL DOESN'T EXIST in active tasks - check if already completed in PlanAssist
        // This prevents duplicating tasks the user marked done before Canvas registered submission
        const alreadyCompleted = await pool.query(
          'SELECT id FROM tasks_completed WHERE user_id = $1 AND url = $2',
          [req.user.id, incomingTask.url]
        );
        if (alreadyCompleted.rows.length > 0) {
          console.log(`\n[SKIP] Task already completed by user: ${incomingTask.title}`);
          continue;
        }

        // SAFETY NET for OSG condensed tasks (assignmentId=null):
        // Check if a non-deleted task with same title + deadline_date already exists.
        // This prevents duplicates when URL format changes or URL lookup misses.
        if (!incomingTask.assignmentId && incomingTask.title && incomingTask.deadlineDate) {
          const osgDuplicate = await pool.query(
            `SELECT id FROM tasks
             WHERE user_id = $1 AND title = $2 AND deadline_date = $3 AND deleted = false`,
            [req.user.id, incomingTask.title, incomingTask.deadlineDate]
          );
          if (osgDuplicate.rows.length > 0) {
            console.log(`\n[SKIP] Duplicate OSG task detected (title+date match): ${incomingTask.title} on ${incomingTask.deadlineDate}`);
            // Update the URL on the existing row to new format
            await pool.query(
              'UPDATE tasks SET url = $1 WHERE id = $2',
              [incomingTask.url, osgDuplicate.rows[0].id]
            );
            continue;
          }
        }
        
        // URL DOESN'T EXIST - Import as new task
        console.log(`\n[NEW] Importing new task: ${incomingTask.title}`);
        console.log(`  courseId=${incomingTask.courseId}, assignmentId=${incomingTask.assignmentId}, pointsPossible=${incomingTask.pointsPossible}`);
        
        // Get max priority for appending new tasks
        const maxPriorityResult = await pool.query(
          'SELECT MAX(priority_order) as max_priority FROM tasks WHERE user_id = $1 AND deleted = false',
          [req.user.id]
        );
        const nextPriority = (maxPriorityResult.rows[0]?.max_priority || 0) + 1;

        const result = await pool.query(
          `INSERT INTO tasks 
           (user_id, title, segment, class, description, url, deadline_date, deadline_time, estimated_time, user_estimated_time, accumulated_time, priority_order, is_new, completed, deleted,
            course_id, assignment_id, points_possible, assignment_group_id, current_score, current_grade, grading_type, unlock_at, lock_at, submitted_at, is_missing, is_late)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)
           ON CONFLICT (user_id, assignment_id) DO UPDATE SET
             title = EXCLUDED.title,
             description = EXCLUDED.description,
             estimated_time = EXCLUDED.estimated_time,
             completed = EXCLUDED.completed,
             class = EXCLUDED.class,
             url = EXCLUDED.url,
             deadline_date = EXCLUDED.deadline_date,
             deadline_time = EXCLUDED.deadline_time,
             course_id = EXCLUDED.course_id,
             points_possible = EXCLUDED.points_possible,
             assignment_group_id = EXCLUDED.assignment_group_id,
             current_score = EXCLUDED.current_score,
             current_grade = EXCLUDED.current_grade,
             grading_type = EXCLUDED.grading_type,
             unlock_at = EXCLUDED.unlock_at,
             lock_at = EXCLUDED.lock_at,
             submitted_at = EXCLUDED.submitted_at,
             is_missing = EXCLUDED.is_missing,
             is_late = EXCLUDED.is_late
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
            incomingTask.completed ?? false,
            false, // Not deleted
            incomingTask.courseId ?? null,
            incomingTask.assignmentId ?? null,
            incomingTask.pointsPossible ?? null,
            incomingTask.assignmentGroupId ?? null,
            incomingTask.currentScore ?? null,
            incomingTask.currentGrade ?? null,
            incomingTask.gradingType || 'points',
            incomingTask.unlockAt ?? null,
            incomingTask.lockAt ?? null,
            incomingTask.submittedAt ?? null,
            incomingTask.isMissing ?? false,
            incomingTask.isLate ?? false
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
    
    // Validate current task exists - if it was completed/deleted, that's okay, just don't save state
    const taskResult = await pool.query(
      'SELECT id, deleted, completed FROM tasks WHERE id = $1 AND user_id = $2',
      [currentTaskIndex, req.user.id]
    );
    
    // If current task is deleted or completed, don't save session state (session is effectively done)
    if (taskResult.rows.length === 0 || taskResult.rows[0].deleted || taskResult.rows[0].completed) {
      console.log(`⚠️  Current task ${currentTaskIndex} is completed/deleted - clearing session state instead of saving`);
      await pool.query('DELETE FROM session_state WHERE user_id = $1', [req.user.id]);
      return res.json({ success: true, message: 'Session cleared (current task complete)' });
    }
    
    await pool.query('DELETE FROM session_state WHERE user_id = $1', [req.user.id]);
    
    // Build partial_task_times JSONB: map of task_id -> accumulated minutes
    // This allows resume to show correct Time Spent for the in-progress task
    let partialTaskTimesJson = null;
    if (req.body.partialTaskTimes && Object.keys(req.body.partialTaskTimes).length > 0) {
      partialTaskTimesJson = JSON.stringify(req.body.partialTaskTimes);
    }
    
    await pool.query(
      `INSERT INTO session_state (user_id, day, period, remaining_time, current_task_index, task_start_time, completed_task_ids, partial_task_times, saved_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)`,
      [req.user.id, day, period, remainingTime, currentTaskIndex, taskStartTime, completedTaskIds, partialTaskTimesJson]
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
        partialTaskTimes: cleanedSession.partial_task_times || {},
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
