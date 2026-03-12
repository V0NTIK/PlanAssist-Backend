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
const { Resend } = require('resend');

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
  allowedHeaders: ['Content-Type', 'Authorization', 'x-cron-secret']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Force UTC timezone for all DB sessions so DATE columns are never shifted
// by the Supabase server timezone (which may be EST/America_New_York)
pool.on('connect', client => {
  client.query("SET TIME ZONE 'UTC'");
});


// Canvas API base URL
const CANVAS_API_BASE = 'https://canvas.oneschoolglobal.com/api/v1';

// Resend email client (optional — only initialized if RESEND_API_KEY is set)
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

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
  const validGrades = ['3', '4', '5', '6', '7', '8', '9', '10', '11', '12'];
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
        isNewUser: user.is_new_user,
        isAdmin: user.is_admin || false
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

    // Credential ban check — after password verified so we don't leak that account exists
    if (user.is_banned) {
      return res.status(403).json({
        error: 'ACCOUNT_BLOCKED',
        message: user.ban_reason || 'This account has been temporarily blocked. Please contact your administrator.'
      });
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
      'SELECT name, grade, canvas_api_token, canvas_api_token_iv, present_periods, calendar_today_centered, calendar_show_homeroom, calendar_show_completed, schedule_enhanced, is_admin FROM users WHERE id = $1',
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
      name: user.name || '',
      grade: user.grade || '',
      canvasApiToken: canvasApiToken,
      presentPeriods: user.present_periods || '2-6',
      schedule,
      calendarTodayCentered: user.calendar_today_centered ?? false,
      calendarShowHomeroom: user.calendar_show_homeroom ?? true,
      calendarShowCompleted: user.calendar_show_completed ?? true,
      schedule_enhanced: user.schedule_enhanced || false,
      is_admin: user.is_admin || false
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
      return res.status(400).json({ error: 'Grade must be one of: 3 through 12' });
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

    // Upsert schedule rows — preserves course_id/course_name from enhanced schedule
    const schedulePromises = [];
    const allSlots = [];
    for (const [day, periods] of Object.entries(schedule)) {
      for (const [period, type] of Object.entries(periods)) {
        const p = parseInt(period);
        allSlots.push({ day, period: p });
        schedulePromises.push(
          pool.query(
            `INSERT INTO schedules (user_id, day, period, type)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, day, period)
             DO UPDATE SET type = EXCLUDED.type`,
            [req.user.id, day, p, type]
          )
        );
      }
    }
    await Promise.all(schedulePromises);
    // Remove slots that no longer exist in the updated schedule
    if (allSlots.length > 0) {
      const slotValues = allSlots.map(sl => `('${sl.day}',${sl.period})`).join(',');
      await pool.query(
        `DELETE FROM schedules WHERE user_id = $1 AND (day, period) NOT IN (${slotValues})`,
        [req.user.id]
      );
    }

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
    // CANVAS_API_BASE is defined at module level
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

      // Grading period scores (current quarter/term only) — from include[]=current_grading_period_scores
      const currentPeriodScore = enrollment.current_period_computed_current_score ?? null;
      const currentPeriodGrade = enrollment.current_period_computed_current_grade ?? null;
      const gradingPeriodId = enrollment.current_grading_period_id ?? null;
      const gradingPeriodTitle = enrollment.current_grading_period_title ?? null;

      console.log(`  Course: ${course.name} | Score: ${currentScore} | Period: ${gradingPeriodTitle} ${currentPeriodScore}`);
      
      await pool.query(
        `INSERT INTO courses (user_id, course_id, name, course_code, current_score, current_grade, final_score, final_grade, enrollment_id,
           current_period_score, current_period_grade, grading_period_id, grading_period_title, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP)
         ON CONFLICT (user_id, course_id)
         DO UPDATE SET 
           name = EXCLUDED.name,
           course_code = EXCLUDED.course_code,
           current_score = EXCLUDED.current_score,
           current_grade = EXCLUDED.current_grade,
           final_score = EXCLUDED.final_score,
           final_grade = EXCLUDED.final_grade,
           current_period_score = EXCLUDED.current_period_score,
           current_period_grade = EXCLUDED.current_period_grade,
           grading_period_id = EXCLUDED.grading_period_id,
           grading_period_title = EXCLUDED.grading_period_title,
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
          enrollment.id || null,
          currentPeriodScore,
          currentPeriodGrade,
          gradingPeriodId,
          gradingPeriodTitle
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
    

    
    // Step 4: Fetch assignments from all courses IN PARALLEL
    // Previously sequential (one request at a time) — now all requests fire simultaneously.
    // 10 courses × ~2s each = ~20s sequential → ~2-3s parallel (slowest single request).
    console.log('\n📋 Fetching assignments (parallel)...');
    const today = new Date();
    const oneMonthFromNow = new Date(today.getTime() + 30 * 24 * 60 * 60 * 1000);

    const courseAssignmentResults = await Promise.all(
      courses.map(async (course) => {
        try {
          const assignmentsResponse = await axios.get(
            `${CANVAS_API_BASE}/courses/${course.id}/assignments?include[]=submission&per_page=100`,
            { headers, timeout: 15000 }
          );
          console.log(`  ✓ Course: ${course.name} - ${assignmentsResponse.data.length} total assignments`);
          return assignmentsResponse.data
            .filter(a => {
              if (!a.due_at) return false;
              const dueDate = new Date(a.due_at);
              return dueDate >= today && dueDate <= oneMonthFromNow;
            })
            .map(a => ({ ...a, course_name: course.name, course_id: course.id }));
        } catch (error) {
          console.error(`  ⚠️  Failed to fetch assignments for ${course.name}:`, error.message);
          return [];
        }
      })
    );

    // Flatten results from all courses into a single array
    const allAssignments = courseAssignmentResults.flat();
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
    
    for (const assignment of allAssignments) {
      const dueDate = new Date(assignment.due_at);
      
      // Always derive deadline_date and deadline_time from the UTC representation.
      // Canvas may return due_at with a timezone offset (e.g. "2026-02-24T23:59:00-05:00")
      // or in UTC (e.g. "2026-02-25T04:59:00Z"). Using dueDate.toISOString() normalises
      // both to UTC, so deadline_date and deadline_time are always a consistent UTC pair.
      // Frontend reconstructs correctly: new Date(`${deadline_date}T${deadline_time}Z`)
      const isoStr = dueDate.toISOString(); // always UTC, e.g. "2026-02-25T04:59:00.000Z"
      const deadlineDate = isoStr.split('T')[0];          // UTC date: "2026-02-25"
      const deadlineTime = isoStr.split('T')[1].split('.')[0]; // UTC time: "04:59:00"
      
      // Get submission data
      const submission = assignment.submission || {};
      const isSubmitted = submission.workflow_state === 'submitted' || submission.workflow_state === 'graded';
      

      
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

      // Only estimate if this task doesn't already have an estimate in the DB.
      // This prevents re-calling AI (Haiku) on every sync for existing tasks.
      const existingEstimate = await pool.query(
        'SELECT estimated_time, user_estimated_time FROM tasks WHERE user_id = $1 AND assignment_id = $2 LIMIT 1',
        [req.user.id, assignment.id]
      );
      let estimatedTime;
      if (existingEstimate.rows.length > 0 && existingEstimate.rows[0].estimated_time != null) {
        // Reuse the existing estimate — no API call needed
        estimatedTime = existingEstimate.rows[0].estimated_time;
        console.log(`  ↩ Reusing existing estimate: ${estimatedTime} min`);
      } else {
        // New task — run full estimation algorithm
        estimatedTime = await estimateTaskTime(taskForEstimation, req.user.id);
      }
      
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
    
    console.log(`✓ Formatted ${tasks.length} tasks for database`);
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
// ADMIN: Refresh all users' course grading period data
// Protected by CRON_SECRET — call once after migration to backfill all users
// POST /api/admin/refresh-courses
// ============================================================================

app.post('/api/admin/refresh-courses', async (req, res) => {
  const secret = req.headers['x-cron-secret'];
  if (!secret || secret !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    console.log('\n🔄 Starting course refresh for all users...');

    // Get all users who have a Canvas token stored
    const usersResult = await pool.query(
      `SELECT id, canvas_api_token, canvas_api_token_iv FROM users
       WHERE canvas_api_token IS NOT NULL AND canvas_api_token != ''`
    );

    let success = 0, failed = 0;

    for (const user of usersResult.rows) {
      try {
        // Decrypt token using same approach as canvas/sync endpoint
        let token;
        try {
          const encryptedParts = user.canvas_api_token.split(':');
          if (encryptedParts.length !== 2) throw new Error('Invalid token format');
          token = decryptToken(encryptedParts[0], user.canvas_api_token_iv, encryptedParts[1]);
          if (!token) throw new Error('Decryption returned null');
        } catch (e) {
          console.log(`  ✗ User ${user.id}: failed to decrypt token - ${e.message}`);
          console.log(`    token value: ${user.canvas_api_token ? user.canvas_api_token.substring(0, 20) + '...' : 'NULL'}`);
          console.log(`    iv value: ${user.canvas_api_token_iv ? user.canvas_api_token_iv.substring(0, 20) + '...' : 'NULL'}`);
          failed++;
          continue;
        }

        const headers = { 'Authorization': `Bearer ${token}` };
        const response = await axios.get(
          `${CANVAS_API_BASE}/courses?enrollment_state=active&include[]=total_scores&include[]=current_grading_period_scores&per_page=100`,
          { headers, timeout: 15000 }
        );

        for (const course of response.data) {
          const enrollment = course.enrollments?.[0] || {};
          const currentScore = enrollment.computed_current_score ?? enrollment.grades?.current_score ?? null;
          const currentGrade = enrollment.computed_current_grade ?? enrollment.grades?.current_grade ?? null;
          const finalScore = enrollment.computed_final_score ?? enrollment.grades?.final_score ?? null;
          const finalGrade = enrollment.computed_final_grade ?? enrollment.grades?.final_grade ?? null;
          const currentPeriodScore = enrollment.current_period_computed_current_score ?? null;
          const currentPeriodGrade = enrollment.current_period_computed_current_grade ?? null;
          const gradingPeriodId = enrollment.current_grading_period_id ?? null;
          const gradingPeriodTitle = enrollment.current_grading_period_title ?? null;

          await pool.query(
            `INSERT INTO courses (user_id, course_id, name, course_code, current_score, current_grade, final_score, final_grade, enrollment_id,
               current_period_score, current_period_grade, grading_period_id, grading_period_title, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP)
             ON CONFLICT (user_id, course_id)
             DO UPDATE SET
               current_score = EXCLUDED.current_score,
               current_grade = EXCLUDED.current_grade,
               final_score = EXCLUDED.final_score,
               final_grade = EXCLUDED.final_grade,
               current_period_score = EXCLUDED.current_period_score,
               current_period_grade = EXCLUDED.current_period_grade,
               grading_period_id = EXCLUDED.grading_period_id,
               grading_period_title = EXCLUDED.grading_period_title,
               updated_at = CURRENT_TIMESTAMP`,
            [user.id, course.id, course.name, course.course_code || null,
             currentScore, currentGrade, finalScore, finalGrade, enrollment.id || null,
             currentPeriodScore, currentPeriodGrade, gradingPeriodId, gradingPeriodTitle]
          );
        }

        console.log(`  ✓ User ${user.id}: refreshed ${response.data.length} courses`);
        success++;
      } catch (err) {
        console.error(`  ✗ User ${user.id}: outer error -`, err.message);
        console.error(err.stack);
        failed++;
      }
    }

    console.log(`\n✅ Course refresh complete: ${success} users updated, ${failed} failed`);
    res.json({ success: true, updated: success, failed });
  } catch (error) {
    console.error('Course refresh error:', error);
    res.status(500).json({ error: 'Refresh failed', details: error.message });
  }
});

// ============================================================================
// DAILY EMAIL CRON ENDPOINT
// Called by GitHub Actions at 10:00 AM UTC Monday-Friday
// Protected by CRON_SECRET environment variable
// ============================================================================

function buildEmailHtml(user, yesterdayTasks, topPriorities, dueToday, dueTomorrow) {
  const firstName = user.name ? user.name.split(' ')[0] : 'there';
  const today = new Date();
  const dateStr = today.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });

  const taskRow = (task, showDeadline = false) => {
    const time = task.user_estimated_time || task.estimated_time;
    const timeStr = time ? `${time} min` : '';
    const deadlineStr = showDeadline && task.deadline_time
      ? new Date(`${task.deadline_date}T${task.deadline_time}Z`).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true })
      : '';
    return `
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #f0f0f0;">
          <span style="font-weight:600;color:#1a1a1a;">${task.title}</span>
          <span style="color:#888;font-size:12px;margin-left:8px;">${task.class || ''}</span>
        </td>
        <td style="padding:8px 12px;border-bottom:1px solid #f0f0f0;color:#666;font-size:13px;white-space:nowrap;">
          ${deadlineStr || timeStr}
        </td>
      </tr>`;
  };

  const section = (title, color, rows) => rows.length === 0 ? '' : `
    <div style="margin-bottom:28px;">
      <h2 style="font-size:16px;font-weight:700;color:${color};margin:0 0 10px 0;padding-bottom:6px;border-bottom:2px solid ${color};">
        ${title}
      </h2>
      <table style="width:100%;border-collapse:collapse;">
        ${rows.join('')}
      </table>
    </div>`;

  return `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <div style="max-width:600px;margin:0 auto;padding:24px 16px;">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#7c3aed,#4f46e5);border-radius:12px;padding:28px 32px;margin-bottom:24px;">
      <div style="font-size:22px;font-weight:800;color:#fff;">📚 PlanAssist</div>
      <div style="font-size:14px;color:#c4b5fd;margin-top:4px;">Good morning, ${firstName}! Here's your day.</div>
      <div style="font-size:13px;color:#a78bfa;margin-top:2px;">${dateStr}</div>
    </div>

    <!-- Body -->
    <div style="background:#fff;border-radius:12px;padding:28px 32px;">

      ${section('✅ Completed Yesterday', '#16a34a', yesterdayTasks.map(t => taskRow(t)))}
      ${section('🎯 Top Priorities Today', '#7c3aed', topPriorities.map(t => taskRow(t)))}
      ${section('⚠️ Due Today', '#dc2626', dueToday.map(t => taskRow(t, true)))}
      ${section('📅 Due Tomorrow', '#d97706', dueTomorrow.map(t => taskRow(t, true)))}

      ${yesterdayTasks.length === 0 && topPriorities.length === 0 && dueToday.length === 0 && dueTomorrow.length === 0
        ? '<p style="color:#888;text-align:center;padding:20px 0;">You\'re all caught up \u2014 nothing due in the next two days!</p>'
        : ''}

      <hr style="border:none;border-top:1px solid #f0f0f0;margin:24px 0;">
      <p style="font-size:12px;color:#aaa;text-align:center;margin:0;">
        You're receiving this because email notifications are enabled in PlanAssist.<br>
        Have a productive day! 🚀
      </p>
    </div>
  </div>
</body>
</html>`;
}

app.post('/api/cron/daily-email', async (req, res) => {
  // Verify the cron secret to prevent unauthorized calls
  const secret = req.headers['x-cron-secret'];
  if (!secret || secret !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    console.log('\n📧 Starting daily email job...');

    // Get all users with email notifications enabled
    const usersResult = await pool.query(
      `SELECT id, name, email FROM users WHERE email_notifications = true`
    );
    const users = usersResult.rows;
    console.log(`Found ${users.length} users to email`);

    // Build date strings in UTC
    const now = new Date();
    const todayStr = now.toISOString().split('T')[0];
    const yesterday = new Date(now);
    yesterday.setUTCDate(yesterday.getUTCDate() - 1);
    // Skip Sunday (0) — yesterday would be Sunday, not a school day
    // GitHub Actions only runs Mon-Fri so yesterday is always a weekday except Monday morning
    const yesterdayStr = yesterday.toISOString().split('T')[0];
    const tomorrow = new Date(now);
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    const tomorrowStr = tomorrow.toISOString().split('T')[0];

    let successCount = 0;
    let failCount = 0;

    for (const user of users) {
      try {
        // 1. What they completed yesterday
        const yesterdayResult = await pool.query(
          `SELECT title, class, estimated_time, actual_time
           FROM tasks_completed
           WHERE user_id = $1
             AND completed_at >= $2::date
             AND completed_at < $3::date
           ORDER BY completed_at DESC`,
          [user.id, yesterdayStr, todayStr]
        );

        // 2. Top priorities today (up to 8 active tasks)
        const prioritiesResult = await pool.query(
          `SELECT title, class, estimated_time, user_estimated_time, deadline_date, deadline_time
           FROM tasks
           WHERE user_id = $1
             AND completed = false
             AND deleted = false
           ORDER BY priority_order ASC NULLS LAST, deadline_date ASC
           LIMIT 8`,
          [user.id]
        );

        // 3. Due today
        const dueTodayResult = await pool.query(
          `SELECT title, class, estimated_time, deadline_date, deadline_time
           FROM tasks
           WHERE user_id = $1
             AND deadline_date = $2
             AND completed = false
             AND deleted = false
           ORDER BY deadline_time ASC NULLS LAST`,
          [user.id, todayStr]
        );

        // 4. Due tomorrow
        const dueTomorrowResult = await pool.query(
          `SELECT title, class, estimated_time, deadline_date, deadline_time
           FROM tasks
           WHERE user_id = $1
             AND deadline_date = $2
             AND completed = false
             AND deleted = false
           ORDER BY deadline_time ASC NULLS LAST`,
          [user.id, tomorrowStr]
        );

        const html = buildEmailHtml(
          user,
          yesterdayResult.rows,
          prioritiesResult.rows,
          dueTodayResult.rows,
          dueTomorrowResult.rows
        );

        await resend.emails.send({
          from: 'PlanAssist <onboarding@resend.dev>',
          to: user.email,
          subject: `📚 Your PlanAssist Morning Briefing — ${new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' })}`,
          html
        });

        console.log(`  ✓ Emailed ${user.name} <${user.email}>`);
        successCount++;
      } catch (userError) {
        console.error(`  ✗ Failed for ${user.email}:`, userError.message);
        failCount++;
      }
    }

    console.log(`\n✅ Daily email job complete: ${successCount} sent, ${failCount} failed\n`);
    res.json({ success: true, sent: successCount, failed: failCount });

  } catch (error) {
    console.error('Daily email job error:', error);
    res.status(500).json({ error: 'Email job failed', details: error.message });
  }
});

// ============================================================================
// PRIORITY ORDER CLEANUP - Run after any sync/save to keep orders clean
// ============================================================================

async function reprioritizeTasks(userId, pool) {
  // Step 1: Null out priority_order for completed, deleted, or ignored tasks
  await pool.query(
    `UPDATE tasks SET priority_order = NULL
     WHERE user_id = $1 AND (completed = true OR deleted = true OR ignored = true)`,
    [userId]
  );

  // Step 2: Renumber remaining active tasks 1,2,3... preserving relative order
  await pool.query(
    `WITH ordered AS (
      SELECT id,
             ROW_NUMBER() OVER (ORDER BY priority_order ASC NULLS LAST, deadline_date ASC, deadline_time ASC NULLS LAST) AS new_order
      FROM tasks
      WHERE user_id = $1 AND completed = false AND deleted = false AND (ignored = false OR ignored IS NULL)
    )
    UPDATE tasks SET priority_order = ordered.new_order
    FROM ordered
    WHERE tasks.id = ordered.id`,
    [userId]
  );
}

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
      `SELECT AVG(COALESCE(current_period_score, current_score)) as avg_score, COUNT(DISTINCT user_id) as student_count
       FROM courses
       WHERE course_id = $1 AND COALESCE(current_period_score, current_score) IS NOT NULL`,
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
              deadline_date,
              deadline_time,
              NULL as priority_order,
              true as completed, completed_at as submitted_at,
              false as is_missing, false as is_late,
              NULL as points_possible, NULL as course_id, NULL as assignment_id
       FROM tasks_completed
       WHERE user_id = $1
         AND deadline_date >= CURRENT_DATE - INTERVAL '30 days'
         AND deadline_date <= CURRENT_DATE + INTERVAL '30 days'`,
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
       WHERE user_id = $1
         AND (split_origin = false OR split_origin IS NULL)
         AND (ignored = false OR ignored IS NULL)
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
        // No assignment_id - fall back to URL matching
        existingTasksResult = await pool.query(
          'SELECT * FROM tasks WHERE user_id = $1 AND url = $2',
          [req.user.id, incomingTask.url]
        );
      }

      if (existingTasksResult.rows.length > 0) {
        // Task EXISTS - Update, but only overwrite Canvas fields if they're actually provided
        console.log(`\n[UPDATE] Found ${existingTasksResult.rows.length} existing task(s) with URL: ${incomingTask.url}`);
        
        const hasCanvasData = incomingTask.courseId !== undefined || incomingTask.assignmentId !== undefined;
        
        for (const existingTask of existingTasksResult.rows) {
          // Skip Canvas sync updates for manually created tasks
          if (existingTask.manually_created) {
            console.log(`[SKIP] Manually created task, skipping sync: ${existingTask.title}`);
            continue;
          }
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
                  is_late = $11,
                  ignored = false,
                  is_new = $12,
                  priority_order = $13
                 WHERE id = $14 AND user_id = $15`,
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
                  existingTask.ignored ? true : existingTask.is_new,       // re-sidebar if was ignored
                  existingTask.ignored ? null : existingTask.priority_order, // strip priority if was ignored
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
                  is_late = $20,
                  ignored = false,
                  is_new = $21,
                  priority_order = $22
                 WHERE id = $23 AND user_id = $24`,
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
                  existingTask.ignored ? true : existingTask.is_new,        // re-sidebar if was ignored
                  existingTask.ignored ? null : (incomingTask.completed ? null : existingTask.priority_order), // strip priority if was ignored or completed
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
          
          // ── Grade change detection ──────────────────────────────────────────
          const scoreChanged = incomingTask.currentScore != null &&
            String(incomingTask.currentScore) !== String(existingTask.current_score);
          const gradeChanged = incomingTask.currentGrade != null &&
            incomingTask.currentGrade !== existingTask.current_grade;
          if (hasCanvasData && (scoreChanged || gradeChanged)) {
            // Get next grade_id for this user
            const gradeIdResult = await pool.query(
              'SELECT COALESCE(MAX(grade_id), 0) + 1 AS next_id FROM tasks WHERE user_id = $1',
              [req.user.id]
            );
            const nextGradeId = gradeIdResult.rows[0].next_id;
            await pool.query(
              'UPDATE tasks SET grade_id = $1 WHERE id = $2 AND user_id = $3',
              [nextGradeId, existingTask.id, req.user.id]
            );
            console.log(`  ★ Grade change detected for task ${existingTask.id}, assigned grade_id=${nextGradeId}`);
          }

          // If task was previously ignored, treat it as a new task for sidebar/count purposes
          if (existingTask.ignored) {
            newCount++;
            console.log(`  ↩ Re-queued ignored task ID ${existingTask.id}: "${existingTask.title}" → sidebar`);
          } else {
            console.log(`  ✓ Updated task ID ${existingTask.id}: "${existingTask.title}"`);
            console.log(`    Canvas data: courseId=${incomingTask.courseId}, assignmentId=${incomingTask.assignmentId}, points=${incomingTask.pointsPossible} (hasCanvasData=${hasCanvasData})`);
            console.log(`    Preserved: priority_order=${existingTask.priority_order}, segment="${existingTask.segment}", user_estimated_time=${existingTask.user_estimated_time}, accumulated_time=${existingTask.accumulated_time}, deleted=${existingTask.deleted}`);
            updatedCount++;
          }
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

        // URL DOESN'T EXIST - check if this was soft-deleted (e.g. split into segments)
        // If a deleted row exists with same assignment_id, skip re-import
        const deletedCheck = await pool.query(
          'SELECT id FROM tasks WHERE user_id = $1 AND assignment_id = $2 AND deleted = true LIMIT 1',
          [req.user.id, incomingTask.assignmentId]
        );
        if (deletedCheck.rows.length > 0 && incomingTask.assignmentId) {
          // Original was split - update the deleted row's canvas fields but don't resurrect
          console.log(`[SPLIT] Skipping re-import of split task: ${incomingTask.title}`);
          continue;
        }

        // URL DOESN'T EXIST - Import as new task
        console.log(`\n[NEW] Importing new task: ${incomingTask.title}`);
        console.log(`  courseId=${incomingTask.courseId}, assignmentId=${incomingTask.assignmentId}, pointsPossible=${incomingTask.pointsPossible}`);
        
        // Get max priority for appending new tasks (only for incomplete tasks)
        let nextPriority = null;
        const isAlreadyCompleted = incomingTask.completed ?? false;
        if (!isAlreadyCompleted) {
          const maxPriorityResult = await pool.query(
            'SELECT MAX(priority_order) as max_priority FROM tasks WHERE user_id = $1 AND deleted = false',
            [req.user.id]
          );
          nextPriority = (maxPriorityResult.rows[0]?.max_priority || 0) + 1;
        }

        const result = await pool.query(
          `INSERT INTO tasks 
           (user_id, title, segment, class, description, url, deadline_date, deadline_time, estimated_time, user_estimated_time, accumulated_time, priority_order, is_new, completed, deleted,
            course_id, assignment_id, points_possible, assignment_group_id, current_score, current_grade, grading_type, unlock_at, lock_at, submitted_at, is_missing, is_late)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)
           ON CONFLICT (user_id, assignment_id) DO UPDATE SET
             title = EXCLUDED.title,
             description = EXCLUDED.description,
             estimated_time = COALESCE(tasks.estimated_time, EXCLUDED.estimated_time),
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
             is_late = EXCLUDED.is_late,
             priority_order = CASE WHEN EXCLUDED.completed THEN NULL ELSE tasks.priority_order END
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
            !isAlreadyCompleted, // Mark as new only if not already completed
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

    // === DISABLED COURSE SUPPRESSION ===
    // Tasks from courses marked enabled=false: ignore them (and delete if 10+ days old)
    {
      const disabledCoursesResult = await pool.query(
        'SELECT course_id FROM courses WHERE user_id = $1 AND enabled = false',
        [req.user.id]
      );
      if (disabledCoursesResult.rows.length > 0) {
        const disabledCourseIds = disabledCoursesResult.rows.map(r => r.course_id);
        const tenDaysAgo = new Date();
        tenDaysAgo.setDate(tenDaysAgo.getDate() - 10);

        // Old tasks (10+ days): hard suppress with deleted=true
        const deleteOld = await pool.query(
          `UPDATE tasks SET deleted = true, ignored = true, is_new = false, priority_order = NULL
           WHERE user_id = $1
             AND deleted = false
             AND course_id = ANY($2::int[])
             AND deadline_date <= $3`,
          [req.user.id, disabledCourseIds, tenDaysAgo.toISOString().slice(0, 10)]
        );

        // Recent tasks: just ignore (don't delete, not old enough)
        const ignoreRecent = await pool.query(
          `UPDATE tasks SET ignored = true, is_new = false, priority_order = NULL
           WHERE user_id = $1
             AND deleted = false
             AND course_id = ANY($2::int[])
             AND deadline_date > $3`,
          [req.user.id, disabledCourseIds, tenDaysAgo.toISOString().slice(0, 10)]
        );

        if (deleteOld.rowCount > 0 || ignoreRecent.rowCount > 0) {
          console.log(`[DISABLED COURSES] Deleted ${deleteOld.rowCount} old tasks, ignored ${ignoreRecent.rowCount} recent tasks from disabled courses`);
        }
      }
    }

    // === MIGRATE: Remove old OSG Accelerate condensed tasks ===
    // Old condensed tasks had title starting with "OSG Accelerate (" and no assignment_id
    // These will be re-synced as individual normal tasks
    // Clean up ALL old OSG Accelerate condensed tasks:
    // - assignment_id IS NULL (condensed tasks never had a real Canvas assignment_id)
    // - manually_created IS NOT TRUE (don't touch user-created tasks)
    // - class contains OSGAccelerate or OSG Accelerate (identifies the course)
    // Real individual OSG tasks from Canvas will have assignment_id set so are unaffected.
    const osgCleanup = await pool.query(
      `UPDATE tasks SET deleted = true, priority_order = NULL, is_new = false
       WHERE user_id = $1
         AND deleted = false
         AND assignment_id IS NULL
         AND (manually_created = false OR manually_created IS NULL)
         AND (class ILIKE '%osgaccelerate%' OR class ILIKE '%osg accelerate%'
              OR title LIKE 'OSG Accelerate (%' OR title LIKE 'OSGAccelerate (%')`,
      [req.user.id]
    );
    if (osgCleanup.rowCount > 0) {
      console.log(`[OSG MIGRATE] Soft-deleted ${osgCleanup.rowCount} old condensed OSG task(s)`);
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
       SET deleted = true, session_active = false
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

    // Reprioritize: null completed/deleted, renumber active tasks cleanly
    await reprioritizeTasks(req.user.id, pool);

    // First-sync fix: if this was the user's first sync (0 existing tasks before),
    // auto-accept all tasks so they appear in Task List immediately (not stuck in sidebar)
    if (updatedCount === 0 && newCount > 0) {
      await pool.query(
        'UPDATE tasks SET is_new = false WHERE user_id = $1',
        [req.user.id]
      );
      console.log(`First sync detected — auto-accepted all ${newCount} tasks`);
    }

    res.json({ 
      success: true, 
      tasks: insertedTasks, 
      stats: { 
        updated: updatedCount, 
        new: newCount,
        cleaned: cleanedUpCount,
        firstSync: updatedCount === 0 && newCount > 0
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
    for (let si = 0; si < segments.length; si++) {
      const segmentName = segments[si];
      const isFirst = si === 0;

      // Build full segment path
      const fullSegment = originalTask.segment 
        ? `${originalTask.segment} - ${segmentName}`
        : segmentName;

      // Carry ALL accumulated_time onto the first segment; others start at 0
      const segAccumulatedTime = isFirst ? (originalTask.accumulated_time || 0) : 0;
      
      const result = await pool.query(
        `INSERT INTO tasks 
         (user_id, title, segment, class, description, url, deadline_date, deadline_time,
          estimated_time, user_estimated_time, accumulated_time, priority_order, is_new, completed,
          course_id, assignment_id, points_possible, assignment_group_id, grading_type,
          deleted, manually_created)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                 $15, NULL, NULL, NULL, 'points', false, false)
         RETURNING *`,
        [
          req.user.id,
          originalTask.title,
          fullSegment,
          originalTask.class,
          originalTask.description,
          originalTask.url,
          originalTask.deadline_date,
          originalTask.deadline_time,
          Math.floor(originalTask.estimated_time / segments.length),
          originalTask.user_estimated_time ? Math.floor(originalTask.user_estimated_time / segments.length) : null,
          segAccumulatedTime, // first segment inherits all prior partial time
          null, // priority set when user adds from sidebar
          true, // is_new so it appears in sidebar
          false,
          originalTask.course_id   // keep course association, but NO assignment_id
        ]
      );
      
      newSegments.push(result.rows[0]);
    }

    // Soft-delete the original task so Sync doesn't re-import it as a new task
    // The Sync will find the segments by assignment_id and update them
    await pool.query(
      'UPDATE tasks SET deleted = true, split_origin = true, priority_order = NULL, session_active = false WHERE id = $1 AND user_id = $2',
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

    // Update priority orders, but only for non-deleted, non-completed tasks
    const updatePromises = taskOrder.map((taskId, index) =>
      pool.query(
        'UPDATE tasks SET priority_order = $1 WHERE id = $2 AND user_id = $3 AND deleted = false AND completed = false AND (ignored = false OR ignored IS NULL)',
        [index + 1, taskId, req.user.id]
      )
    );

    await Promise.all(updatePromises);

    // Clean up: null completed/deleted, renumber active tasks
    await reprioritizeTasks(req.user.id, pool);
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
      'UPDATE tasks SET deleted = true, priority_order = NULL, session_active = false WHERE id = $1 AND user_id = $2',
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

// ============================================================================
// SESSION ROUTES (v2 — single-task, task-table-backed)
// ============================================================================

// GET /api/sessions/tasks — return all incomplete, non-deleted, non-homeroom tasks
// in priority order for the Sessions page
app.get('/api/sessions/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, segment, class, url, deadline_date, deadline_time,
              estimated_time, user_estimated_time, accumulated_time, session_active,
              priority_order, points_possible
       FROM tasks
       WHERE user_id = $1
         AND completed = false
         AND deleted = false
         AND LOWER(class) NOT LIKE '%homeroom%'
       ORDER BY priority_order ASC NULLS LAST, deadline_date ASC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get session tasks error:', error);
    res.status(500).json({ error: 'Failed to get session tasks' });
  }
});

// POST /api/sessions/start/:taskId — mark a task as actively in session
app.post('/api/sessions/start/:taskId', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    // Clear any other active sessions for this user first
    await pool.query(
      'UPDATE tasks SET session_active = false WHERE user_id = $1 AND session_active = true',
      [req.user.id]
    );
    await pool.query(
      'UPDATE tasks SET session_active = true WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Start session error:', error);
    res.status(500).json({ error: 'Failed to start session' });
  }
});

// POST /api/sessions/pause/:taskId — save elapsed time and clear active flag
app.post('/api/sessions/pause/:taskId', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { accumulatedTime } = req.body;
    await pool.query(
      'UPDATE tasks SET session_active = false, accumulated_time = $1 WHERE id = $2 AND user_id = $3',
      [accumulatedTime, taskId, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Pause session error:', error);
    res.status(500).json({ error: 'Failed to pause session' });
  }
});

// ============================================================================
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
    
    // For segment tasks: check if another segment of the same task already exists
    // in tasks_completed. If so, merge by accumulating estimated_time + actual_time.
    // Always fire leaderboard + feed regardless (each segment is real work done).
    if (task.segment && task.url) {
      const existingCompletion = await pool.query(
        'SELECT id, estimated_time, actual_time FROM tasks_completed WHERE user_id = $1 AND url = $2',
        [req.user.id, task.url]
      );

      if (existingCompletion.rows.length > 0) {
        // Merge: add this segment's time onto the existing entry
        const existing = existingCompletion.rows[0];
        const newEstimated = (existing.estimated_time || 0) + (task.user_estimated_time || task.estimated_time || 0);
        const newActual = (existing.actual_time || 0) + (timeSpent || 0);
        await pool.query(
          `UPDATE tasks_completed
           SET estimated_time = $1, actual_time = $2, completed_at = CURRENT_TIMESTAMP
           WHERE id = $3`,
          [newEstimated, newActual, existing.id]
        );
        console.log(`[SEGMENT MERGE] Updated tasks_completed for "${task.title}" (+${timeSpent}min actual, +${task.user_estimated_time || task.estimated_time}min est)`);
      } else {
        // First segment to complete — insert normally
        await pool.query(
          `INSERT INTO tasks_completed (id, user_id, title, class, description, url, deadline_date, deadline_time, estimated_time, actual_time, completed_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)`,
          [
            task.id, req.user.id, task.title, task.class, task.description, task.url,
            task.deadline_date, task.deadline_time,
            task.user_estimated_time || task.estimated_time,
            timeSpent
          ]
        );
      }
    } else {
      // Non-segment task: insert normally
      await pool.query(
        `INSERT INTO tasks_completed (id, user_id, title, class, description, url, deadline_date, deadline_time, estimated_time, actual_time, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)`,
        [
          task.id, req.user.id, task.title, task.class, task.description, task.url,
          task.deadline_date, task.deadline_time,
          task.user_estimated_time || task.estimated_time,
          timeSpent
        ]
      );
    }
    
    // Mark task as deleted instead of removing from database
    // This preserves the URL in the database so it won't be re-imported during sync
    await pool.query(
      'UPDATE tasks SET deleted = true, priority_order = NULL, session_active = false WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    
    // Update leaderboard and completion feed only when appropriate:
    // - Non-segment tasks: always fire
    // - Segment tasks with canonical URL: only fire when this is the LAST remaining segment
    // - Tasks with planassist URL (manual tasks): always fire (they don't share URL meaningfully)
    const PLANASSIST_URL = 'https://planassist.onrender.com/';
    let shouldFireFeed = true;
    if (task.segment && task.url && task.url !== PLANASSIST_URL) {
      // Check if any other non-completed, non-deleted segment siblings remain
      const remainingSegments = await pool.query(
        `SELECT id FROM tasks
         WHERE user_id = $1 AND url = $2 AND segment IS NOT NULL
           AND deleted = false AND completed = false AND id != $3`,
        [req.user.id, task.url, taskId]
      );
      if (remainingSegments.rows.length > 0) {
        shouldFireFeed = false; // more segments still to go
      }
    }
    if (shouldFireFeed) {
      updateLeaderboardOnCompletion(req.user.id).catch(err => console.error('Leaderboard update failed:', err));
      addToCompletionFeed(req.user.id, task.title, task.class).catch(err => console.error('Feed update failed:', err));
    }
    
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
    
    // Mark task as ignored: is_new=false so it leaves the sidebar, ignored=true so
    // it won't re-enter the sidebar until the next sync resets ignored, deleted stays FALSE
    // so the task remains in the DB and can be reviewed in Resolved Tasks.
    await pool.query(
      'UPDATE tasks SET ignored = true, is_new = false, priority_order = NULL WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    
    console.log(`✓ Task ${taskId} marked as ignored by user ${req.user.id}`);
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

// ============================================================================
// AGENDAS
// ============================================================================

// GET /api/agendas — list all unfinished agendas for the user, with task data
app.get('/api/agendas', authenticateToken, async (req, res) => {
  try {
    const agendasResult = await pool.query(
      `SELECT id, name, task_ids, finished, created_at
       FROM agendas
       WHERE user_id = $1 AND finished = false
       ORDER BY created_at ASC`,
      [req.user.id]
    );

    // For each agenda, fetch the current task data
    const agendas = await Promise.all(agendasResult.rows.map(async (agenda) => {
      const taskIds = agenda.task_ids || [];
      if (taskIds.length === 0) return { ...agenda, tasks: [] };

      const tasksResult = await pool.query(
        `SELECT id, title, segment, class, url, deadline_date, deadline_time,
                estimated_time, user_estimated_time, accumulated_time,
                session_active, priority_order, completed, deleted
         FROM tasks
         WHERE id = ANY($1) AND user_id = $2`,
        [taskIds, req.user.id]
      );

      // Preserve original ordering; exclude deleted tasks (completed agenda tasks are soft-deleted)
      const taskMap = {};
      tasksResult.rows.forEach(t => { taskMap[t.id] = t; });
      const tasks = taskIds.map(id => taskMap[id]).filter(t => t && !t.deleted);

      return { ...agenda, tasks };
    }));

    res.json(agendas);
  } catch (error) {
    console.error('Get agendas error:', error);
    res.status(500).json({ error: 'Failed to get agendas' });
  }
});

// POST /api/agendas — create a new agenda
app.post('/api/agendas', authenticateToken, async (req, res) => {
  try {
    const { name, taskIds } = req.body;
    if (!name || !taskIds || taskIds.length === 0 || taskIds.length > 3) {
      return res.status(400).json({ error: 'Name and 1-3 task IDs are required' });
    }

    const result = await pool.query(
      `INSERT INTO agendas (user_id, name, task_ids)
       VALUES ($1, $2, $3)
       RETURNING id, name, task_ids, finished, created_at`,
      [req.user.id, name.trim(), taskIds]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Create agenda error:', error);
    res.status(500).json({ error: 'Failed to create agenda' });
  }
});

// DELETE /api/agendas/:agendaId — delete an agenda
app.delete('/api/agendas/:agendaId', authenticateToken, async (req, res) => {
  try {
    const { agendaId } = req.params;
    await pool.query(
      'DELETE FROM agendas WHERE id = $1 AND user_id = $2',
      [agendaId, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Delete agenda error:', error);
    res.status(500).json({ error: 'Failed to delete agenda' });
  }
});

// PATCH /api/agendas/:agendaId/finish — mark agenda as finished
app.patch('/api/agendas/:agendaId/finish', authenticateToken, async (req, res) => {
  try {
    const { agendaId } = req.params;
    await pool.query(
      'UPDATE agendas SET finished = true, updated_at = NOW() WHERE id = $1 AND user_id = $2',
      [agendaId, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Finish agenda error:', error);
    res.status(500).json({ error: 'Failed to finish agenda' });
  }
});

// ============================================================================
// ENHANCE SCHEDULE — save lesson-course mappings + zoom numbers
// ============================================================================

// POST /api/schedule/enhance
// Body: { lessons: [{day, period, courseId, courseName}], zoomNumbers: [{courseId, zoomNumber}] }
app.post('/api/schedule/enhance', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { lessons, zoomNumbers } = req.body;
    await client.query('BEGIN');

    // Update course_id/course_name on existing schedules rows for Lesson slots
    for (const lesson of (lessons || [])) {
      await client.query(
        `UPDATE schedules
         SET course_id = $1, course_name = $2
         WHERE user_id = $3 AND day = $4 AND period = $5`,
        [lesson.courseId || null, lesson.courseName || null, req.user.id, lesson.day, lesson.period]
      );
    }

    // Update zoom numbers on courses
    for (const z of (zoomNumbers || [])) {
      if (z.zoomNumber) {
        await client.query(
          `UPDATE courses SET zoom_number = $1 WHERE id = $2 AND user_id = $3`,
          [z.zoomNumber, z.courseId, req.user.id]
        );
      }
    }

    // Mark user as enhanced
    await client.query(
      `UPDATE users SET schedule_enhanced = true WHERE id = $1`,
      [req.user.id]
    );

    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Enhance schedule error:', error);
    res.status(500).json({ error: 'Failed to enhance schedule' });
  } finally {
    client.release();
  }
});

// GET /api/schedule/lessons — get lesson-course mappings for this user
app.get('/api/schedule/lessons', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.day, s.period, s.course_id, s.course_name, c.zoom_number
       FROM schedules s
       LEFT JOIN courses c ON c.id = s.course_id AND c.user_id = $1
       WHERE s.user_id = $1 AND s.type = 'Lesson' AND s.course_id IS NOT NULL`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get schedule lessons error:', error);
    res.status(500).json({ error: 'Failed to get schedule lessons' });
  }
});

// ============================================================================
// ITINERARY SLOTS
// ============================================================================

// GET /api/itinerary — get today's itinerary slots (day param from client)
app.get('/api/itinerary', authenticateToken, async (req, res) => {
  try {
    const { day } = req.query; // e.g. 'Monday'
    const result = await pool.query(
      `SELECT is2.period, is2.agenda_id, a.name AS agenda_name, a.task_ids, a.finished
       FROM itinerary_slots is2
       LEFT JOIN agendas a ON a.id = is2.agenda_id
       WHERE is2.user_id = $1 AND is2.day = $2`,
      [req.user.id, day]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get itinerary error:', error);
    res.status(500).json({ error: 'Failed to get itinerary' });
  }
});

// PUT /api/itinerary — assign (or clear) an agenda to a period slot
// Body: { day, period, agendaId } — agendaId: null to clear
app.put('/api/itinerary', authenticateToken, async (req, res) => {
  try {
    const { day, period, agendaId } = req.body;
    if (agendaId === null || agendaId === undefined) {
      // Clear the slot
      await pool.query(
        `DELETE FROM itinerary_slots WHERE user_id = $1 AND day = $2 AND period = $3`,
        [req.user.id, day, period]
      );
    } else {
      await pool.query(
        `INSERT INTO itinerary_slots (user_id, day, period, agenda_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, day, period)
         DO UPDATE SET agenda_id = $4`,
        [req.user.id, day, period, agendaId]
      );
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Update itinerary error:', error);
    res.status(500).json({ error: 'Failed to update itinerary' });
  }
});


// ============================================================================
// TUTORIALS
// ============================================================================

// GET /api/tutorials?day=Monday — get tutorials for a specific day
app.get('/api/tutorials', authenticateToken, async (req, res) => {
  try {
    const { day } = req.query;
    const query = day
      ? 'SELECT * FROM tutorials WHERE user_id = $1 AND day = $2 ORDER BY period ASC'
      : 'SELECT * FROM tutorials WHERE user_id = $1 ORDER BY day, period ASC';
    const params = day ? [req.user.id, day] : [req.user.id];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Get tutorials error:', error);
    res.status(500).json({ error: 'Failed to get tutorials' });
  }
});

// PUT /api/tutorials — upsert a tutorial for a day/period
app.put('/api/tutorials', authenticateToken, async (req, res) => {
  try {
    const { day, period, zoomNumber, topic } = req.body;
    if (!day || !period) {
      return res.status(400).json({ error: 'Day and period are required' });
    }
    const result = await pool.query(
      `INSERT INTO tutorials (user_id, day, period, zoom_number, topic)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, day, period)
       DO UPDATE SET zoom_number = $4, topic = $5
       RETURNING *`,
      [req.user.id, day, period, zoomNumber || null, topic || null]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Upsert tutorial error:', error);
    res.status(500).json({ error: 'Failed to save tutorial' });
  }
});

// DELETE /api/tutorials — remove a tutorial for a day/period
app.delete('/api/tutorials', authenticateToken, async (req, res) => {
  try {
    const { day, period } = req.body;
    await pool.query(
      'DELETE FROM tutorials WHERE user_id = $1 AND day = $2 AND period = $3',
      [req.user.id, day, period]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Delete tutorial error:', error);
    res.status(500).json({ error: 'Failed to delete tutorial' });
  }
});


// POST /api/tasks/normalize — compact priority_order to remove gaps after deletions
app.post('/api/tasks/normalize', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      `UPDATE tasks SET priority_order = NULL
       WHERE user_id = $1 AND (completed = true OR deleted = true)`,
      [req.user.id]
    );
    await pool.query(
      `WITH ordered AS (
         SELECT id,
           ROW_NUMBER() OVER (ORDER BY priority_order ASC NULLS LAST, deadline_date ASC, deadline_time ASC NULLS LAST) AS new_order
         FROM tasks
         WHERE user_id = $1 AND deleted = false AND completed = false AND priority_order IS NOT NULL
       )
       UPDATE tasks SET priority_order = ordered.new_order
       FROM ordered WHERE tasks.id = ordered.id`,
      [req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Normalize priority error:', error);
    res.status(500).json({ error: 'Failed to normalize priority' });
  }
});


// POST /api/tasks/manual — create a user-defined task
app.post('/api/tasks/manual', authenticateToken, async (req, res) => {
  try {
    const { title, deadlineDate, deadlineTime, estimatedTime, description, url } = req.body;
    if (!title || !deadlineDate || !deadlineTime || !estimatedTime) {
      return res.status(400).json({ error: 'title, deadlineDate, deadlineTime, and estimatedTime are required' });
    }
    // Get next priority
    const maxP = await pool.query(
      'SELECT MAX(priority_order) as max_p FROM tasks WHERE user_id = $1 AND deleted = false AND completed = false',
      [req.user.id]
    );
    const nextPriority = (maxP.rows[0].max_p || 0) + 1;

    const result = await pool.query(
      `INSERT INTO tasks
         (user_id, title, segment, class, description, url, deadline_date, deadline_time,
          estimated_time, user_estimated_time, accumulated_time, priority_order,
          is_new, completed, deleted, manually_created,
          course_id, assignment_id, points_possible, assignment_group_id, grading_type)
       VALUES ($1, $2, NULL, 'Personal', $3, $4, $5, $6, $7, $7, 0, $8,
               true, false, false, true,
               NULL, NULL, NULL, NULL, 'not_graded')
       RETURNING *`,
      [
        req.user.id, title, description || null, url || 'https://planassist.onrender.com/',
        deadlineDate, deadlineTime || null, estimatedTime, nextPriority
      ]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Create manual task error:', error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});


// ============================================================================
// ADMIN MIDDLEWARE + AUDIT HELPER
// ============================================================================

const requireAdmin = async (req, res, next) => {
  try {
    const result = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
    if (!result.rows[0]?.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: 'Auth check failed' });
  }
};

const auditLog = async (adminId, adminName, action, targetUserId, targetUserName, details = {}) => {
  try {
    await pool.query(
      `INSERT INTO admin_audit_log (admin_id, admin_name, action, target_user_id, target_user_name, details)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [adminId, adminName, action, targetUserId || null, targetUserName || null, JSON.stringify(details)]
    );
  } catch (err) {
    console.error('[AUDIT] Failed to write audit log:', err.message);
  }
};

// ============================================================================
// ADMIN: ANNOUNCEMENTS
// ============================================================================

// GET /api/admin/announcements — all active (and recent inactive) for admin view
app.get('/api/admin/announcements', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.*, u.name as author_name
       FROM announcements a
       LEFT JOIN users u ON u.id = a.author_id
       ORDER BY a.created_at DESC LIMIT 50`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

// GET /api/announcements — active announcements for current user (with dismissal state)
app.get('/api/announcements', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.*,
         EXISTS(
           SELECT 1 FROM announcement_dismissals d
           WHERE d.announcement_id = a.id AND d.user_id = $1
         ) as dismissed
       FROM announcements a
       WHERE a.is_active = true
       ORDER BY a.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

// POST /api/admin/announcements — create announcement
app.post('/api/admin/announcements', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { message, type } = req.body;
    if (!message || !type) return res.status(400).json({ error: 'message and type required' });
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const adminName = adminRes.rows[0]?.name || 'Admin';
    const result = await pool.query(
      `INSERT INTO announcements (author_id, author_name, message, type) VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.user.id, adminName, message, type]
    );
    await auditLog(req.user.id, adminName, 'CREATE_ANNOUNCEMENT', null, null, { message, type });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create announcement' });
  }
});

// PATCH /api/admin/announcements/:id/deactivate
app.patch('/api/admin/announcements/:id/deactivate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await pool.query(
      `UPDATE announcements SET is_active = false, deactivated_at = NOW() WHERE id = $1`,
      [req.params.id]
    );
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'DEACTIVATE_ANNOUNCEMENT', null, null, { announcement_id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to deactivate' });
  }
});

// POST /api/announcements/:id/dismiss — user dismisses a dismissible banner
app.post('/api/announcements/:id/dismiss', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO announcement_dismissals (user_id, announcement_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [req.user.id, req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to dismiss' });
  }
});

// ============================================================================
// ADMIN: USER MANAGEMENT
// ============================================================================

// GET /api/admin/users — list all users with stats
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.grade, u.is_admin, u.is_banned, u.ban_reason,
              u.is_new_user, u.present_periods, u.schedule_enhanced, u.created_at,
              COUNT(DISTINCT t.id) FILTER (WHERE t.deleted = false AND t.completed = false) AS active_tasks,
              COUNT(DISTINCT t.id) FILTER (WHERE t.is_new = true AND t.deleted = false) AS new_tasks,
              MAX(tc.completed_at) AS last_completion,
              COUNT(DISTINCT tc.id) AS total_completed,
              EXISTS(SELECT 1 FROM tasks st WHERE st.user_id = u.id AND st.session_active = true) AS in_session
       FROM users u
       LEFT JOIN tasks t ON t.user_id = u.id
       LEFT JOIN tasks_completed tc ON tc.user_id = u.id
       GROUP BY u.id
       ORDER BY u.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET /api/admin/users/:id — single user detail + tasks
app.get('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userRes = await pool.query(
      `SELECT id, name, email, grade, is_admin, is_banned, ban_reason, is_new_user,
              present_periods, schedule_enhanced, created_at FROM users WHERE id = $1`,
      [req.params.id]
    );
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const tasksRes = await pool.query(
      `SELECT id, title, segment, class, deadline_date, deadline_time, priority_order, completed, deleted, is_new, manually_created
       FROM tasks WHERE user_id = $1 ORDER BY priority_order ASC NULLS LAST, deadline_date ASC LIMIT 100`,
      [req.params.id]
    );
    const newTasksRes = await pool.query(
      `SELECT id, title, segment, class, deadline_date, deadline_time, manually_created
       FROM tasks WHERE user_id = $1 AND is_new = true AND deleted = false
       ORDER BY deadline_date ASC`,
      [req.params.id]
    );
    const completedRes = await pool.query(
      `SELECT title, class, actual_time, estimated_time, completed_at
       FROM tasks_completed WHERE user_id = $1 ORDER BY completed_at DESC LIMIT 20`,
      [req.params.id]
    );
    res.json({ user: userRes.rows[0], tasks: tasksRes.rows, newTasks: newTasksRes.rows, recentCompletions: completedRes.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user detail' });
  }
});

// PATCH /api/admin/users/:id — edit user fields (name, grade, present_periods, is_admin)
app.patch('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, grade, present_periods, is_admin } = req.body;
    const targetId = parseInt(req.params.id);

    // Prevent self-demotion
    if (is_admin === false && targetId === req.user.id) {
      return res.status(400).json({ error: 'You cannot remove your own admin status.' });
    }

    const fields = [];
    const vals = [];
    let idx = 1;
    if (name !== undefined)            { fields.push(`name = $${idx++}`);            vals.push(name); }
    if (grade !== undefined)           { fields.push(`grade = $${idx++}`);           vals.push(grade); }
    if (present_periods !== undefined) { fields.push(`present_periods = $${idx++}`); vals.push(present_periods); }
    if (is_admin !== undefined)        { fields.push(`is_admin = $${idx++}`);        vals.push(is_admin); }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    vals.push(targetId);
    await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id = $${idx}`, vals);

    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const targetRes = await pool.query('SELECT name FROM users WHERE id = $1', [targetId]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'EDIT_USER', targetId, targetRes.rows[0]?.name, req.body);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// POST /api/admin/users/:id/ban
app.post('/api/admin/users/:id/ban', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    const targetId = parseInt(req.params.id);
    if (targetId === req.user.id) return res.status(400).json({ error: 'You cannot ban yourself.' });

    await pool.query(
      `UPDATE users SET is_banned = true, ban_reason = $1 WHERE id = $2`,
      [reason || 'This account has been temporarily blocked. Please contact your administrator.', targetId]
    );
    // Invalidate sessions by clearing their token can't be done in JWT without a blacklist,
    // but next login attempt will be rejected.
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const targetRes = await pool.query('SELECT name FROM users WHERE id = $1', [targetId]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'BAN_USER', targetId, targetRes.rows[0]?.name, { reason });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to ban user' });
  }
});

// POST /api/admin/users/:id/unban
app.post('/api/admin/users/:id/unban', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const targetId = parseInt(req.params.id);
    await pool.query(`UPDATE users SET is_banned = false, ban_reason = NULL WHERE id = $1`, [targetId]);
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const targetRes = await pool.query('SELECT name FROM users WHERE id = $1', [targetId]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'UNBAN_USER', targetId, targetRes.rows[0]?.name, {});
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to unban user' });
  }
});

// POST /api/admin/users/:id/clear-token — clear Canvas API token
app.post('/api/admin/users/:id/clear-token', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id;
    await pool.query(
      `UPDATE users SET canvas_api_token = NULL, canvas_api_token_iv = NULL WHERE id = $1`, [targetId]
    );
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const targetRes = await pool.query('SELECT name FROM users WHERE id = $1', [targetId]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'CLEAR_CANVAS_TOKEN', parseInt(targetId), targetRes.rows[0]?.name, {});
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear token' });
  }
});


// POST /api/admin/users/:id/tasks-scan — clear all is_new flags and reassign priority_order
app.post('/api/admin/users/:id/tasks-scan', authenticateToken, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const targetId = parseInt(req.params.id);
    await client.query('BEGIN');

    // Step 1: Clear all is_new flags for this user
    await client.query(
      `UPDATE tasks SET is_new = false WHERE user_id = $1 AND is_new = true AND deleted = false`,
      [targetId]
    );

    // Step 2: Reassign priority_order sequentially for all active, non-new tasks
    // preserving their existing relative order (by current priority_order then deadline)
    await client.query(
      `WITH ordered AS (
         SELECT id, ROW_NUMBER() OVER (
           ORDER BY priority_order ASC NULLS LAST, deadline_date ASC NULLS LAST
         ) AS new_order
         FROM tasks
         WHERE user_id = $1 AND deleted = false AND completed = false
       )
       UPDATE tasks SET priority_order = ordered.new_order
       FROM ordered WHERE tasks.id = ordered.id`,
      [targetId]
    );

    await client.query('COMMIT');

    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const targetRes = await pool.query('SELECT name FROM users WHERE id = $1', [targetId]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'TASKS_SCAN', targetId, targetRes.rows[0]?.name, {});

    // Return updated task list for the user
    const tasksRes = await pool.query(
      `SELECT id, title, segment, class, deadline_date, priority_order, completed, deleted, is_new, manually_created
       FROM tasks WHERE user_id = $1 ORDER BY priority_order ASC NULLS LAST, deadline_date ASC LIMIT 100`,
      [targetId]
    );
    res.json({ success: true, tasks: tasksRes.rows });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Tasks scan error:', err);
    res.status(500).json({ error: 'Tasks scan failed' });
  } finally {
    client.release();
  }
});

// DELETE /api/admin/tasks/:taskId — admin delete a specific task
app.delete('/api/admin/tasks/:taskId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const taskRes = await pool.query('SELECT title, user_id FROM tasks WHERE id = $1', [req.params.taskId]);
    if (taskRes.rows.length === 0) return res.status(404).json({ error: 'Task not found' });
    const task = taskRes.rows[0];
    await pool.query('UPDATE tasks SET deleted = true, priority_order = NULL WHERE id = $1', [req.params.taskId]);
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const targetRes = await pool.query('SELECT name FROM users WHERE id = $1', [task.user_id]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'DELETE_TASK', task.user_id, targetRes.rows[0]?.name, { task_title: task.title, task_id: req.params.taskId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// ============================================================================
// ADMIN: DIAGNOSTICS
// ============================================================================

// GET /api/admin/diagnostics
app.get('/api/admin/diagnostics', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // a) Users who haven't synced recently (no tasks updated in 7 days)
    const staleSyncRes = await pool.query(
      `SELECT u.id, u.name, u.email, u.grade, MAX(t.created_at) as last_task_import
       FROM users u
       LEFT JOIN tasks t ON t.user_id = u.id
       WHERE u.is_new_user = false
       GROUP BY u.id
       HAVING MAX(t.created_at) < NOW() - INTERVAL '7 days' OR MAX(t.created_at) IS NULL
       ORDER BY last_task_import ASC NULLS FIRST LIMIT 20`
    );

    // b) Users with no Canvas token set
    const noTokenRes = await pool.query(
      `SELECT id, name, email, grade FROM users
       WHERE (canvas_api_token IS NULL OR canvas_api_token = '')
         AND is_new_user = false
       ORDER BY name ASC`
    );

    // c) Tasks with missing/null deadlines
    const badTasksRes = await pool.query(
      `SELECT t.id, t.title, t.class, u.name as user_name, u.grade
       FROM tasks t JOIN users u ON u.id = t.user_id
       WHERE t.deleted = false AND t.completed = false AND t.deadline_date IS NULL
       ORDER BY u.name ASC LIMIT 30`
    );

    // d) Duplicate tasks (same url + user, multiple active)
    const dupRes = await pool.query(
      `SELECT u.name as user_name, t.url, COUNT(*) as count
       FROM tasks t JOIN users u ON u.id = t.user_id
       WHERE t.deleted = false AND t.completed = false AND t.url IS NOT NULL
         AND t.segment IS NULL
       GROUP BY u.name, t.url HAVING COUNT(*) > 1
       ORDER BY count DESC LIMIT 20`
    );

    // e) Completion stats by grade
    const statsRes = await pool.query(
      `SELECT u.grade,
              COUNT(DISTINCT u.id) as user_count,
              COUNT(tc.id) as total_completions,
              ROUND(AVG(tc.actual_time)::numeric, 1) as avg_actual_min,
              ROUND(AVG(tc.estimated_time)::numeric, 1) as avg_estimated_min
       FROM users u
       LEFT JOIN tasks_completed tc ON tc.user_id = u.id
       WHERE u.grade IS NOT NULL AND u.grade != ''
       GROUP BY u.grade ORDER BY NULLIF(regexp_replace(u.grade, '[^0-9]', '', 'g'), '')::int ASC NULLS LAST`
    );

    // f) New user signups (last 14 days)
    const newUsersRes = await pool.query(
      `SELECT id, name, email, grade, created_at, is_new_user
       FROM users
       WHERE created_at > NOW() - INTERVAL '3 days'
       ORDER BY created_at DESC`
    );

    res.json({
      staleSyncs: staleSyncRes.rows,
      noToken: noTokenRes.rows,
      badTasks: badTasksRes.rows,
      duplicates: dupRes.rows,
      gradeStats: statsRes.rows,
      newUsers: newUsersRes.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch diagnostics' });
  }
});

// ============================================================================
// ADMIN: AUDIT LOG
// ============================================================================

app.get('/api/admin/audit-log', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM admin_audit_log ORDER BY created_at DESC LIMIT 200`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// Start server


// ── ACCOUNT & ANALYTICS ENDPOINTS ────────────────────────────────────────────

// GET resolved tasks (completed OR deleted-and-ignored, excluding split_origin)
app.get('/api/tasks/resolved', authenticateToken, async (req, res) => {
  try {
    const { sort = 'created_at', search = '' } = req.query;
    const orderCol = sort === 'deadline' ? 'deadline_date, deadline_time' : 'created_at';
    const searchParam = search ? `%${search}%` : '%';
    const result = await pool.query(
      `SELECT t.*,
              tc.completed_at, tc.actual_time AS session_actual_time
       FROM tasks t
       LEFT JOIN tasks_completed tc ON tc.id = t.id AND tc.user_id = t.user_id
       WHERE t.user_id = $1
         AND (t.split_origin IS NOT TRUE)
         AND (t.completed = TRUE OR t.ignored = TRUE)
         AND (t.title ILIKE $2 OR t.class ILIKE $2)
       ORDER BY ${orderCol} DESC NULLS LAST`,
      [req.user.id, searchParam]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get resolved tasks error:', error);
    res.status(500).json({ error: 'Failed to get resolved tasks' });
  }
});

// PATCH actual_time for a completed task in tasks_completed
app.patch('/api/tasks/:taskId/actual-time', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { actualTime } = req.body;
    if (typeof actualTime !== 'number' || actualTime < 0) {
      return res.status(400).json({ error: 'actualTime must be a non-negative number' });
    }
    await pool.query(
      'UPDATE tasks_completed SET actual_time = $1 WHERE id = $2 AND user_id = $3',
      [actualTime, taskId, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Update actual time error:', error);
    res.status(500).json({ error: 'Failed to update actual time' });
  }
});

// POST restore a resolved task back to the task list
app.post('/api/tasks/:taskId/restore', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;

    const taskResult = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    if (taskResult.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }
    const task = taskResult.rows[0];

    // Delete any tasks_completed entry
    await pool.query(
      'DELETE FROM tasks_completed WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    // Determine insertion position by deadline (same algorithm as Add All to List)
    const activeTasks = await pool.query(
      `SELECT id, deadline_date, deadline_time, priority_order
       FROM tasks WHERE user_id = $1 AND deleted = FALSE AND completed = FALSE
       AND split_origin IS NOT TRUE
       ORDER BY priority_order ASC NULLS LAST`,
      [req.user.id]
    );

    const taskDeadline = new Date(
      `${task.deadline_date}T${task.deadline_time || '23:59:00'}Z`
    );

    let insertPosition = activeTasks.rows.length + 1;
    for (const t of activeTasks.rows) {
      const d = new Date(`${t.deadline_date}T${t.deadline_time || '23:59:00'}Z`);
      if (taskDeadline < d) {
        insertPosition = t.priority_order || activeTasks.rows.indexOf(t) + 1;
        break;
      }
    }

    // Shift tasks at or after insertPosition up by 1
    await pool.query(
      `UPDATE tasks SET priority_order = priority_order + 1
       WHERE user_id = $1 AND deleted = FALSE AND completed = FALSE
       AND split_origin IS NOT TRUE
       AND priority_order >= $2`,
      [req.user.id, insertPosition]
    );

    // Restore the task
    await pool.query(
      `UPDATE tasks SET completed = FALSE, deleted = FALSE, ignored = FALSE,
        is_new = FALSE, priority_order = $1
       WHERE id = $2 AND user_id = $3`,
      [insertPosition, taskId, req.user.id]
    );

    // Renormalize to clean up any gaps
    await reprioritizeTasks(req.user.id, pool);

    res.json({ success: true });
  } catch (error) {
    console.error('Restore task error:', error);
    res.status(500).json({ error: 'Failed to restore task' });
  }
});

// PATCH course enabled toggle
app.patch('/api/courses/:courseId/enabled', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { enabled } = req.body;
    await pool.query(
      'UPDATE courses SET enabled = $1 WHERE id = $2 AND user_id = $3',
      [enabled, courseId, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Toggle course enabled error:', error);
    res.status(500).json({ error: 'Failed to update course' });
  }
});

// GET help content (public — any authenticated user)
app.get('/api/help', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT content, updated_at FROM help_content WHERE id = 1');
    res.json(result.rows[0] || { content: '', updated_at: null });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get help content' });
  }
});

// PUT help content (admin only)
app.put('/api/admin/help', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { content } = req.body;
    await pool.query(
      'UPDATE help_content SET content = $1, updated_at = CURRENT_TIMESTAMP, updated_by = $2 WHERE id = 1',
      [content, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update help content' });
  }
});

// GET grade_id-ordered grades from DB (last 20 graded tasks by grade_id)
app.get('/api/canvas/grades', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, assignment_id, title, class, url, points_possible,
              current_score, current_grade, grading_type, submitted_at, grade_id
       FROM tasks
       WHERE user_id = $1
         AND grade_id IS NOT NULL
         AND deleted = false
       ORDER BY grade_id DESC
       LIMIT 20`,
      [req.user.id]
    );

    const graded = result.rows.map(t => ({
      id: t.id,
      assignmentId: t.assignment_id,
      assignmentName: t.title,
      courseName: t.class,
      score: t.current_score != null ? parseFloat(t.current_score) : null,
      pointsPossible: t.points_possible != null ? parseFloat(t.points_possible) : null,
      grade: t.current_grade,
      gradingType: t.grading_type || 'points',
      gradedAt: t.submitted_at,
      htmlUrl: t.url,
      gradeId: t.grade_id,
    }));

    res.json(graded);
  } catch (error) {
    console.error('Grades fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch grades' });
  }
});

// POST grade mini-sync — checks only tasks due in the last 30 days for grade changes
app.post('/api/canvas/grades/mini-sync', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv FROM users WHERE id = $1',
      [req.user.id]
    );
    const userRow = userResult.rows[0];
    if (!userRow?.canvas_api_token) return res.status(400).json({ error: 'No Canvas token' });

    const encryptedParts = userRow.canvas_api_token.split(':');
    const token = decryptToken(encryptedParts[0], userRow.canvas_api_token_iv, encryptedParts[1]);
    if (!token) return res.status(500).json({ error: 'Failed to decrypt token' });

    const headers = { Authorization: `Bearer ${token}` };
    const canvasBase = CANVAS_API_BASE;

    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    // Get distinct course_ids with tasks due in last 30 days
    const coursesResult = await pool.query(
      `SELECT DISTINCT course_id FROM tasks
       WHERE user_id = $1 AND course_id IS NOT NULL AND deleted = false
         AND deadline_date >= $2`,
      [req.user.id, thirtyDaysAgo.toISOString().slice(0, 10)]
    );
    const courseIds = coursesResult.rows.map(r => r.course_id);

    if (courseIds.length === 0) return res.json({ updated: 0 });

    // Fetch assignment submissions for those courses
    const submissionResults = await Promise.allSettled(
      courseIds.map(cid =>
        axios.get(
          `${canvasBase}/courses/${cid}/submissions?student_ids[]=self&include[]=assignment&per_page=100`,
          { headers, timeout: 10000 }
        ).then(r => r.data.map(s => ({ ...s, _courseId: cid })))
      )
    );

    const allSubs = submissionResults
      .filter(r => r.status === 'fulfilled')
      .flatMap(r => r.value);

    if (allSubs.length === 0) return res.json({ updated: 0 });

    // Get max grade_id for this user
    const maxResult = await pool.query(
      'SELECT COALESCE(MAX(grade_id), 0) AS max_id FROM tasks WHERE user_id = $1',
      [req.user.id]
    );
    let nextGradeId = parseInt(maxResult.rows[0].max_id) + 1;
    let updatedCount = 0;

    for (const sub of allSubs) {
      if (sub.score == null && !sub.grade) continue;

      // Find matching task in DB
      const taskResult = await pool.query(
        `SELECT id, current_score, current_grade FROM tasks
         WHERE user_id = $1 AND assignment_id = $2 AND deleted = false LIMIT 1`,
        [req.user.id, sub.assignment_id]
      );
      if (taskResult.rows.length === 0) continue;

      const task = taskResult.rows[0];
      const scoreChanged = sub.score != null && String(sub.score) !== String(task.current_score);
      const gradeChanged = sub.grade != null && sub.grade !== task.current_grade;

      if (scoreChanged || gradeChanged) {
        await pool.query(
          `UPDATE tasks SET current_score = $1, current_grade = $2, grade_id = $3
           WHERE id = $4 AND user_id = $5`,
          [sub.score, sub.grade, nextGradeId, task.id, req.user.id]
        );
        nextGradeId++;
        updatedCount++;
      }
    }

    console.log(`[GRADE MINI-SYNC] user=${req.user.id}, updated=${updatedCount}`);
    res.json({ updated: updatedCount });
  } catch (error) {
    console.error('Grade mini-sync error:', error.message);
    res.status(500).json({ error: 'Failed to run grade mini-sync' });
  }
});

// GET Canvas announcements (all active courses, last 20 total)
app.get('/api/canvas/announcements', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv FROM users WHERE id = $1',
      [req.user.id]
    );
    const userRow = userResult.rows[0];
    if (!userRow?.canvas_api_token) return res.status(400).json({ error: 'No Canvas token' });
    const encryptedParts = userRow.canvas_api_token.split(':');
    const token = decryptToken(encryptedParts[0], userRow.canvas_api_token_iv, encryptedParts[1]);
    if (!token) return res.status(500).json({ error: 'Failed to decrypt token' });
    const headers = { Authorization: `Bearer ${token}` };
    const canvasBase = CANVAS_API_BASE;

    // Get distinct course_ids from user's tasks
    const coursesResult = await pool.query(
      'SELECT DISTINCT course_id FROM tasks WHERE user_id = $1 AND course_id IS NOT NULL AND deleted = false',
      [req.user.id]
    );
    const courseIds = coursesResult.rows.map(r => r.course_id);

    // Try the dedicated announcements endpoint first (works on some Canvas instances),
    // fall back to discussion_topics?only_announcements=true if it 404s
    let announcementData = [];
    try {
      const contextCodes = courseIds.map(cid => `course_${cid}`).join('&context_codes[]=');
      const announcementsResp = await axios.get(
        `${canvasBase}/announcements?context_codes[]=${contextCodes}&per_page=20`,
        { headers, timeout: 10000 }
      );
      announcementData = Array.isArray(announcementsResp.data)
        ? announcementsResp.data.map(a => {
            // context_code is like "course_12345" — extract course id
            const cid = a.context_code ? parseInt(a.context_code.replace('course_', '')) : null;
            return { ...a, _courseId: cid };
          })
        : [];
      console.log(`[announcements] dedicated endpoint: ${announcementData.length} items`);
    } catch (e) {
      console.log(`[announcements] dedicated endpoint failed (${e.response?.status}), trying per-course fallback`);
      const results = await Promise.allSettled(
        courseIds.map(cid =>
          axios.get(`${canvasBase}/courses/${cid}/discussion_topics?only_announcements=true&per_page=10`,
            { headers, timeout: 10000 })
            .then(r => r.data.map(a => ({ ...a, _courseId: cid })))
        )
      );
      announcementData = results.filter(r => r.status === 'fulfilled').flatMap(r => r.value);
      console.log(`[announcements] per-course fallback: ${announcementData.length} items`);
    }
    const results = { fulfilled: true, data: announcementData };
    // Wrap so the sort/map below works uniformly
    const allAnnouncements = announcementData;

    // Get course names
    const courseNames = {};
    (await pool.query('SELECT course_id, name FROM courses WHERE user_id = $1', [req.user.id]))
      .rows.forEach(r => { courseNames[r.course_id] = r.name; });

    const announcements = allAnnouncements
      .sort((a, b) => new Date(b.posted_at || b.created_at) - new Date(a.posted_at || a.created_at))
      .slice(0, 20)
      .map(a => ({
        id: a.id,
        title: a.title,
        body: a.message ? a.message.replace(/<[^>]*>/g, '').trim().slice(0, 300) : null,
        courseId: a._courseId,
        courseName: courseNames[a._courseId] || `Course ${a._courseId}`,
        postedAt: a.posted_at || a.created_at,
        htmlUrl: a.html_url,
      }));

    res.json(announcements);
  } catch (error) {
    console.error('Announcements error:', error.message);
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

// GET Canvas discussions (all active courses, last 20 total, excluding announcements)
app.get('/api/canvas/discussions', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv FROM users WHERE id = $1',
      [req.user.id]
    );
    const userRow = userResult.rows[0];
    if (!userRow?.canvas_api_token) return res.status(400).json({ error: 'No Canvas token' });
    const encryptedParts = userRow.canvas_api_token.split(':');
    const token = decryptToken(encryptedParts[0], userRow.canvas_api_token_iv, encryptedParts[1]);
    if (!token) return res.status(500).json({ error: 'Failed to decrypt token' });
    const headers = { Authorization: `Bearer ${token}` };
    const canvasBase = CANVAS_API_BASE;

    const coursesResult = await pool.query(
      'SELECT DISTINCT course_id FROM tasks WHERE user_id = $1 AND course_id IS NOT NULL AND deleted = false',
      [req.user.id]
    );
    const courseIds = coursesResult.rows.map(r => r.course_id);

    const discussionResults = await Promise.allSettled(
      courseIds.map(cid =>
        axios.get(`${canvasBase}/courses/${cid}/discussion_topics?per_page=10`,
          { headers, timeout: 10000 })
          .then(r => r.data.filter(d => !d.is_announcement).map(d => ({ ...d, _courseId: cid })))
      )
    );

    const failedDiscussions = discussionResults.filter(r => r.status === 'rejected');
    if (failedDiscussions.length > 0) {
      console.log(`[discussions] ${failedDiscussions.length} course(s) failed, first: ${failedDiscussions[0].reason?.message}`);
    }
    console.log(`[discussions] ${discussionResults.filter(r => r.status === 'fulfilled').length} courses succeeded`);

    const courseNames = {};
    (await pool.query('SELECT course_id, name FROM courses WHERE user_id = $1', [req.user.id]))
      .rows.forEach(r => { courseNames[r.course_id] = r.name; });

    const discussions = discussionResults
      .filter(r => r.status === 'fulfilled')
      .flatMap(r => r.value)
      .sort((a, b) => new Date(b.last_reply_at || b.posted_at || b.created_at) - new Date(a.last_reply_at || a.posted_at || a.created_at))
      .slice(0, 20)
      .map(d => ({
        id: d.id,
        title: d.title,
        body: d.message ? d.message.replace(/<[^>]*>/g, '').trim().slice(0, 300) : null,
        courseId: d._courseId,
        courseName: courseNames[d._courseId] || `Course ${d._courseId}`,
        postedAt: d.posted_at || d.created_at,
        lastReplyAt: d.last_reply_at || null,
        unreadCount: d.unread_count || 0,
        htmlUrl: d.html_url,
      }));

    res.json(discussions);
  } catch (error) {
    console.error('Discussions error:', error.message);
    res.status(500).json({ error: 'Failed to fetch discussions' });
  }
});

// GET Canvas activity stream (grades, announcements, discussions, etc.)
app.get('/api/canvas/activity', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv FROM users WHERE id = $1',
      [req.user.id]
    );
    const userRow = userResult.rows[0];
    if (!userRow?.canvas_api_token) {
      return res.status(400).json({ error: 'No Canvas token configured' });
    }
    const encryptedParts = userRow.canvas_api_token.split(':');
    const token = decryptToken(encryptedParts[0], userRow.canvas_api_token_iv, encryptedParts[1]);
    if (!token) {
      return res.status(500).json({ error: 'Failed to decrypt Canvas token' });
    }
    const headers = { Authorization: `Bearer ${token}` };

    const response = await axios.get(
      `${CANVAS_API_BASE}/users/self/activity_stream?per_page=50`,
      { headers, timeout: 15000 }
    );

    const items = (Array.isArray(response.data) ? response.data : []).map(item => ({
      id: item.id,
      type: item.type,                          // 'Grade', 'Announcement', 'DiscussionTopic', 'Message', 'Submission', 'Conversation', 'Conference', 'Collaboration'
      title: item.title || item.subject || null,
      body: item.message || item.body || null,
      courseId: item.course_id || null,
      courseName: item.context_name || null,
      createdAt: item.created_at,
      updatedAt: item.updated_at,
      htmlUrl: item.html_url || null,
      // Grade-specific
      score: item.score ?? null,
      pointsPossible: item.assignment?.points_possible ?? null,
      grade: item.grade ?? null,
      gradingType: item.assignment?.grading_type ?? null,
      assignmentName: item.assignment?.title ?? item.title ?? null,
      // Unread
      unread: item.unread_count > 0 || false,
    }));

    res.json(items);
  } catch (error) {
    console.error('Canvas activity stream error:', error.message);
    res.status(500).json({ error: 'Failed to fetch activity stream' });
  }
});

app.listen(PORT, () => {
  console.log(`\n==============================================`);
  console.log(`  PlanAssist API v2.0 - REDESIGNED`);
  console.log(`  Server running on port ${PORT}`);
  console.log(`  Title/Segment System Active`);
  console.log(`  Advanced AI Estimation Enabled`);
  console.log(`==============================================\n`);
});
