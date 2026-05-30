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

// Force UTC timezone for all DB sessions so DATE columns are never shifted
// by the Supabase server timezone (which may be EST/America_New_York)
pool.on('connect', client => {
  client.query("SET TIME ZONE 'UTC'");
});


// Canvas API base URL
const CANVAS_API_BASE = 'https://canvas.oneschoolglobal.com/api/v1';
const CANVAS_BASE_URL = 'https://canvas.oneschoolglobal.com';

// Build a usable URL for a Canvas assignment, falling back if html_url is null.
// Old quizzes use /quizzes/:quiz_id; all others use /assignments/:assignment_id.
const buildAssignmentUrl = (a, courseId) => {
  if (a.html_url) return a.html_url;
  const cid = courseId || a.course_id;
  if (a.quiz_id) return `${CANVAS_BASE_URL}/courses/${cid}/quizzes/${a.quiz_id}`;
  if (a.id)      return `${CANVAS_BASE_URL}/courses/${cid}/assignments/${a.id}`;
  return CANVAS_BASE_URL;
};


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
// CAMPUS TIMEZONE HELPERS (for streak shield timestamp generation)
// ============================================================================

// Campus UTC offsets — dst = hours during Daylight Saving Time (Mar–Nov),
// standard = hours during Standard Time (Nov–Mar).
// All OSG NA campuses that observe DST follow the US/Canada schedule.
const CAMPUS_UTC_OFFSETS = {
  'Ashland':        { standard: -5, dst: -4 },
  'Barbados':       { standard: -4, dst: -4 },
  'Calgary':        { standard: -7, dst: -6 },
  'Chesapeake':     { standard: -5, dst: -4 },
  'Chicago':        { standard: -6, dst: -5 },
  'Council Bluffs': { standard: -6, dst: -5 },
  'Des Moines':     { standard: -6, dst: -5 },
  'Detroit':        { standard: -5, dst: -4 },
  'Edmonton':       { standard: -7, dst: -6 },
  'Gothenburg':     { standard: -6, dst: -5 },
  'Hamilton':       { standard: -5, dst: -4 },
  'Indianapolis':   { standard: -5, dst: -4 },
  'Jamaica':        { standard: -5, dst: -5 },
  'Kalispell':      { standard: -7, dst: -6 },
  'Knoxville':      { standard: -5, dst: -4 },
  'Los Angeles':    { standard: -8, dst: -7 },
  'Maple Creek':    { standard: -6, dst: -6 },
  'Minneapolis':    { standard: -6, dst: -5 },
  'Montreal':       { standard: -5, dst: -4 },
  'Mossley':        { standard: -5, dst: -4 },
  'New England':    { standard: -5, dst: -4 },
  'New York':       { standard: -5, dst: -4 },
  'Oxbow':          { standard: -6, dst: -6 },
  'Pembina':        { standard: -6, dst: -5 },
  'Portland':       { standard: -8, dst: -7 },
  'Redwood Falls':  { standard: -6, dst: -5 },
  'Regina':         { standard: -6, dst: -6 },
  'Rideau Lakes':   { standard: -5, dst: -4 },
  'Rochester':      { standard: -5, dst: -4 },
  'San Antonio':    { standard: -6, dst: -5 },
  'San Francisco':  { standard: -8, dst: -7 },
  'Seattle':        { standard: -8, dst: -7 },
  'St. Vincent':    { standard: -4, dst: -4 },
  'Stonewall':      { standard: -6, dst: -5 },
  'Trinidad':       { standard: -4, dst: -4 },
  'Vancouver':      { standard: -8, dst: -7 },
};

// Returns true if the given date is in US/Canada DST (2nd Sun March → 1st Sun November).
function isDSTOnDate(dateStr) {
  const [y, m, d] = dateStr.split('-').map(Number);
  // DST starts: 2nd Sunday of March
  const dstStart = new Date(y, 2, 1); // March 1
  dstStart.setDate(1 + (7 - dstStart.getDay()) % 7 + 7); // 2nd Sunday
  // DST ends: 1st Sunday of November
  const dstEnd = new Date(y, 10, 1); // November 1
  dstEnd.setDate(1 + (7 - dstEnd.getDay()) % 7); // 1st Sunday
  const check = new Date(y, m - 1, d);
  return check >= dstStart && check < dstEnd;
}

// Given a campus-tz YYYY-MM-DD date string and a campus name, returns a UTC
// timestamp (Date object) representing noon on that campus date.
// Noon campus-time is safely within the day regardless of DST transitions.
function campusDateToUTC(dateStr, campus) {
  const entry = CAMPUS_UTC_OFFSETS[campus] || CAMPUS_UTC_OFFSETS['Ashland'];
  const offsetHours = isDSTOnDate(dateStr) ? entry.dst : entry.standard;
  // noon campus-time = 12:00:00 campus = (12 - offsetHours) UTC
  const [y, m, d] = dateStr.split('-').map(Number);
  const utcHour = 12 - offsetHours; // e.g. UTC-4: noon EDT = 16:00 UTC
  return new Date(Date.UTC(y, m - 1, d, utcHour, 0, 0));
}

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


// ── Canvas token decryption cache (15-min TTL) ──────────────────────────────
// Avoids repeated decrypt calls across Main Sync, Background Sync, Course Sync, Grade Sync.
// Cache is invalidated immediately when a user saves a new Canvas token.
const _tokenCache = new Map(); // userId → { token: string, expiresAt: number }

function getCachedToken(userId) {
  const entry = _tokenCache.get(userId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { _tokenCache.delete(userId); return null; }
  return entry.token;
}

function setCachedToken(userId, token) {
  _tokenCache.set(userId, { token, expiresAt: Date.now() + 15 * 60 * 1000 });
}

function invalidateCachedToken(userId) {
  _tokenCache.delete(userId);
  console.log(`[TOKEN CACHE] Invalidated cache for user ${userId}`);
}

// Helper: decrypt and cache the Canvas token for a given user row
// Accepts the raw user row from DB ({ canvas_api_token, canvas_api_token_iv })
function getDecryptedCanvasToken(userId, userRow) {
  const cached = getCachedToken(userId);
  if (cached) {
    console.log(`[TOKEN CACHE] Cache hit for user ${userId}`);
    return cached;
  }
  if (!userRow?.canvas_api_token || !userRow?.canvas_api_token_iv) return null;
  const parts = userRow.canvas_api_token.split(':');
  if (parts.length !== 2) return null;
  const token = decryptToken(parts[0], userRow.canvas_api_token_iv, parts[1]);
  if (token) setCachedToken(userId, token);
  return token;
}

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
    const { email: rawEmail, password } = req.body;
    const email = rawEmail?.trim().toLowerCase();

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
    const { email: rawEmail, password } = req.body;
    const email = rawEmail?.trim().toLowerCase();

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
        isNewUser: user.is_new_user,
        showInFeed: user.show_in_feed !== false
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});


// ── Campus → period range lookup ────────────────────────────────────────────
const CAMPUS_PERIODS = {
  'Ashland':        '2-6',
  'Barbados':       '1-5',
  'Calgary':        '4-8',
  'Chesapeake':     '2-6',
  'Chicago':        '3-7',
  'Council Bluffs': '3-7',
  'Des Moines':     '3-7',
  'Detroit':        '2-6',
  'Edmonton':       '4-8',
  'Gothenburg':     '3-7',
  'Hamilton':       '2-6',
  'Indianapolis':   '2-6',
  'Jamaica':        '2-6',
  'Kalispell':      '4-8',
  'Knoxville':      '2-6',
  'Los Angeles':    '4-8',
  'Maple Creek':    '3-7',
  'Minneapolis':    '3-7',
  'Montreal':       '2-6',
  'Mossley':        '2-6',
  'New England':    '2-6',
  'New York':       '2-6',
  'Oxbow':          '3-7',
  'Pembina':        '3-7',
  'Portland':       '4-8',
  'Redwood Falls':  '3-7',
  'Regina':         '3-7',
  'Rideau Lakes':   '2-6',
  'Rochester':      '2-6',
  'San Antonio':    '3-7',
  'San Francisco':  '4-8',
  'Seattle':        '4-8',
  'St. Vincent':    '1-5',
  'Stonewall':      '3-7',
  'Trinidad':       '1-5',
  'Vancouver':      '4-8',
};
const CAMPUS_PERIODS_DST = {
  'Ashland':        '2-6',
  'Barbados':       '2-6',
  'Calgary':        '4-8',
  'Chesapeake':     '2-6',
  'Chicago':        '3-7',
  'Council Bluffs': '3-7',
  'Des Moines':     '3-7',
  'Detroit':        '2-6',
  'Edmonton':       '4-8',
  'Gothenburg':     '3-7',
  'Hamilton':       '2-6',
  'Indianapolis':   '2-6',
  'Jamaica':        '3-7',
  'Kalispell':      '4-8',
  'Knoxville':      '2-6',
  'Los Angeles':    '4-8',
  'Maple Creek':    '3-7',
  'Minneapolis':    '3-7',
  'Montreal':       '2-6',
  'Mossley':        '2-6',
  'New England':    '2-6',
  'New York':       '2-6',
  'Oxbow':          '3-7',
  'Pembina':        '3-7',
  'Portland':       '4-8',
  'Redwood Falls':  '3-7',
  'Regina':         '3-7',
  'Rideau Lakes':   '2-6',
  'Rochester':      '2-6',
  'San Antonio':    '3-7',
  'San Francisco':  '4-8',
  'Seattle':        '4-8',
  'St. Vincent':    '2-6',
  'Stonewall':      '3-7',
  'Trinidad':       '2-6',
  'Vancouver':      '4-8',
};

const VALID_CAMPUSES = Object.keys(CAMPUS_PERIODS);

// Returns true if North American DST is currently active, based purely on the
// UTC date — independent of the server's local timezone.
// NA DST: 2nd Sunday in March 02:00 local → 1st Sunday in November 02:00 local.
// We use noon UTC on transition dates as a safe threshold (all NA campuses have
// transitioned by then regardless of their exact UTC offset).
function isNADST(date = new Date()) {
  const year = date.getUTCFullYear();
  const march1Day = new Date(Date.UTC(year, 2, 1)).getUTCDay();
  const secondSunMarch = (march1Day === 0 ? 1 : 8 - march1Day) + 7;
  const dstStart = new Date(Date.UTC(year, 2, secondSunMarch, 12, 0, 0));
  const nov1Day = new Date(Date.UTC(year, 10, 1)).getUTCDay();
  const firstSunNov = nov1Day === 0 ? 1 : 8 - nov1Day;
  const dstEnd = new Date(Date.UTC(year, 10, firstSunNov, 12, 0, 0));
  return date >= dstStart && date < dstEnd;
}

// Returns the period range string for the given campus.
function getCampusPeriods(campus) {
  return CAMPUS_PERIODS[campus] || CAMPUS_PERIODS['Ashland'];
}

// Returns the DST-aware period range string for the given campus.
// This is the value that should be stored in tz_periods and returned to clients.
function getEffectivePeriods(campus) {
  return isNADST()
    ? (CAMPUS_PERIODS_DST[campus] || CAMPUS_PERIODS_DST['Ashland'])
    : (CAMPUS_PERIODS[campus]     || CAMPUS_PERIODS['Ashland']);
}

// ============================================================================
// ACCOUNT SETUP ROUTES
// ============================================================================

// Get account setup
app.get('/api/account/setup', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT name, grade, canvas_api_token, canvas_api_token_iv, campus, tz_periods, calendar_show_homeroom, calendar_show_completed, calendar_show_prev_week, calendar_show_current_week, calendar_show_next_week1, calendar_show_next_week2, calendar_show_weekends, schedule_enhanced, is_admin, show_in_feed, last_sync FROM users WHERE id = $1',
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
      campus: user.campus || 'Ashland',
      schedule,
      calendarShowHomeroom: user.calendar_show_homeroom ?? true,
      calendarShowCompleted: user.calendar_show_completed ?? true,
      calendarShowPrevWeek: user.calendar_show_prev_week ?? false,
      calendarShowCurrentWeek: user.calendar_show_current_week ?? true,
      calendarShowNextWeek1: user.calendar_show_next_week1 ?? false,
      calendarShowNextWeek2: user.calendar_show_next_week2 ?? false,
      calendarShowWeekends: user.calendar_show_weekends ?? true,
      schedule_enhanced: user.schedule_enhanced || false,
      is_admin: user.is_admin || false,
      showInFeed: user.show_in_feed !== false,
      lastSync: user.last_sync || null,
      // Return the DST-aware period range so the frontend can use it directly.
      // Recomputed at request time so it stays current across DST transitions
      // without requiring the user to re-save their settings.
      tzPeriods: getEffectivePeriods(user.campus || 'Ashland')
    });
  } catch (error) {
    console.error('Get account setup error:', error);
    res.status(500).json({ error: 'Failed to get account setup' });
  }
});

// Save account setup
app.post('/api/account/setup', authenticateToken, async (req, res) => {
  try {
    const { grade, canvasApiToken, campus, schedule, calendarTodayCentered, calendarShowHomeroom, calendarShowCompleted,
            calendarShowPrevWeek, calendarShowCurrentWeek, calendarShowNextWeek1, calendarShowNextWeek2, calendarShowWeekends } = req.body;

    // Derive DST-aware period ranges from campus
    const resolvedCampus = VALID_CAMPUSES.includes(campus) ? campus : 'Ashland';
    const tzPeriods = getEffectivePeriods(resolvedCampus);

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

    // Invalidate the in-memory token cache so next sync uses fresh decrypted token
    if (canvasApiToken && canvasApiToken.trim()) {
      invalidateCachedToken(req.user.id);
    }

    // Only update token columns when a token is actually provided
    if (canvasApiToken && canvasApiToken.trim()) {
      await pool.query(
        `UPDATE users SET grade = $1, canvas_api_token = $2, canvas_api_token_iv = $3,
          campus = $4, tz_periods = $5, is_new_user = false,
          calendar_show_homeroom = $6, calendar_show_completed = $7,
          calendar_show_prev_week = $8, calendar_show_current_week = $9,
          calendar_show_next_week1 = $10, calendar_show_next_week2 = $11,
          calendar_show_weekends = $12
         WHERE id = $13`,
        [grade, encryptedToken, iv, resolvedCampus, tzPeriods,
         calendarShowHomeroom ?? false,
         calendarShowCompleted ?? true,
         calendarShowPrevWeek ?? false,
         calendarShowCurrentWeek ?? true,
         calendarShowNextWeek1 ?? false,
         calendarShowNextWeek2 ?? false,
         calendarShowWeekends ?? true,
         req.user.id]
      );
    } else {
      // No token provided — update everything except the token columns
      await pool.query(
        `UPDATE users SET grade = $1,
          campus = $2, tz_periods = $3, is_new_user = false,
          calendar_show_homeroom = $4, calendar_show_completed = $5,
          calendar_show_prev_week = $6, calendar_show_current_week = $7,
          calendar_show_next_week1 = $8, calendar_show_next_week2 = $9,
          calendar_show_weekends = $10
         WHERE id = $11`,
        [grade, resolvedCampus, tzPeriods,
         calendarShowHomeroom ?? false,
         calendarShowCompleted ?? true,
         calendarShowPrevWeek ?? false,
         calendarShowCurrentWeek ?? true,
         calendarShowNextWeek1 ?? false,
         calendarShowNextWeek2 ?? false,
         calendarShowWeekends ?? true,
         req.user.id]
      );
    }

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
// ============================================================================
// POST /api/canvas/sync — MAIN SYNC
// Triggered: manual Sync button, or on first login / new user.
// Fetches ALL courses assignments (up to 90 days out) in parallel, estimates times,
// then calls sync-save for batched upsert.
// ============================================================================
app.post('/api/canvas/sync', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log(`\n=== MAIN SYNC START for user ${userId} ===`);

    // Step 0: Get and decrypt Canvas token (with cache)
    const userResult = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv FROM users WHERE id = $1',
      [userId]
    );
    const canvasToken = getDecryptedCanvasToken(userId, userResult.rows[0]);
    if (!canvasToken) {
      return res.status(400).json({ error: 'No Canvas API token found. Please add your token in Settings.' });
    }
    const headers = { Authorization: `Bearer ${canvasToken}`, Accept: 'application/json' };

    // Step 1: Fetch all active courses (needed to know which courses to scan)
    console.log('[MAIN SYNC] Fetching active courses...');
    let courses;
    try {
      const resp = await axios.get(
        `${CANVAS_API_BASE}/courses?per_page=100`,
        { headers, timeout: 15000 }
      );
      courses = (resp.data || []).filter(c => {
        const enrollmentState = c.enrollments?.[0]?.enrollment_state;
        return !enrollmentState || enrollmentState === 'active' || enrollmentState === 'invited';
      });
      console.log(`[MAIN SYNC] ${courses.length} active courses found`);
    } catch (err) {
      if (err.response?.status === 401) {
        return res.status(400).json({ error: 'Canvas API token is invalid or expired. Please update your token in Settings.' });
      }
      return res.status(500).json({ error: 'Failed to fetch courses from Canvas', details: err.message });
    }

    // Step 2: Fetch assignments for ALL courses IN PARALLEL (90-day window)
    const ninetyDaysOut = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
    const now = new Date();
    console.log('[MAIN SYNC] Fetching assignments in parallel...');
    const courseResults = await Promise.all(
      courses.map(async (course) => {
        try {
          const resp = await axios.get(
            `${CANVAS_API_BASE}/courses/${course.id}/assignments?include[]=submission&per_page=100`,
            { headers, timeout: 15000 }
          );
          const all = Array.isArray(resp.data) ? resp.data : [];
          console.log(`  [MAIN SYNC] ${course.name}: ${all.length} assignments`);
          return all
            .filter(a => {
              // Old-style Canvas quizzes often have due_at=null but lock_at set.
              // Fall back to lock_at as the effective deadline so they aren't silently dropped.
              const effectiveDue = a.due_at || a.lock_at;
              if (!effectiveDue) return false;
              const d = new Date(effectiveDue);
              return d >= now && d <= ninetyDaysOut;
            })
            .map(a => ({ ...a, course_name: course.name, course_id: course.id }));
        } catch (err) {
          console.warn(`  [MAIN SYNC] Failed to fetch ${course.name}: ${err.message}`);
          return [];
        }
      })
    );
    const allAssignments = courseResults.flat();
    console.log(`[MAIN SYNC] Total assignments to process: ${allAssignments.length}`);

    // Step 3: Estimate times for new assignments (reuse existing estimates)
    console.log('[MAIN SYNC] Estimating task times...');
    const tasks = [];
    for (const a of allAssignments) {
      const effectiveDue = a.due_at || a.lock_at;   // lock_at fallback for old quizzes
      const dueDate = new Date(effectiveDue);
      const isoStr = dueDate.toISOString();
      const deadlineDate = isoStr.split('T')[0];
      const deadlineTime = isoStr.split('T')[1].split('.')[0];
      const sub = a.submission || {};
      const isSubmitted = sub.workflow_state === 'submitted' || sub.workflow_state === 'graded';

      // Check for existing estimate first (no AI call needed if it exists)
      const existingEst = await pool.query(
        'SELECT estimated_time FROM tasks WHERE user_id = $1 AND assignment_id = $2 LIMIT 1',
        [userId, a.id]
      );
      let estimatedTime;
      if (existingEst.rows.length > 0 && existingEst.rows[0].estimated_time != null) {
        estimatedTime = existingEst.rows[0].estimated_time;
      } else {
        estimatedTime = await estimateTaskTime({
          title: a.name, class: a.course_name, url: buildAssignmentUrl(a, a.course_id),
          assignmentId: a.id, courseId: a.course_id,
          pointsPossible: a.points_possible, gradingType: a.grading_type,
          description: a.description || ''
        }, userId);
      }

      tasks.push({
        title: a.name, segment: null, class: a.course_name,
        description: a.description || '', url: buildAssignmentUrl(a, a.course_id),
        deadlineDate, deadlineTime, estimatedTime,
        courseId: a.course_id, assignmentId: a.id,
        quizId: a.quiz_id ?? null,             // classic quiz ID (null for non-quiz assignments)
        pointsPossible: a.points_possible ?? null,
        assignmentGroupId: a.assignment_group_id ?? null,
        currentScore: sub.score ?? null,
        currentGrade: sub.grade ? String(sub.grade).slice(0, 50) : null,
        gradingType: (a.grading_type || 'points').slice(0, 50),
        unlockAt: a.unlock_at ?? null, lockAt: a.lock_at ?? null,
        submittedAt: sub.submitted_at ?? null,
        isMissing: sub.missing ?? false, isLate: sub.late ?? false,
        completed: isSubmitted
      });
    }

    console.log(`[MAIN SYNC] Returning ${tasks.length} tasks to frontend`);
    res.json({ tasks, stats: { courses: courses.length, assignments: tasks.length } });

  } catch (err) {
    console.error('[MAIN SYNC] Error:', err.message);
    console.error(err.stack);
    res.status(500).json({ error: 'Failed to sync with Canvas', details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error' });
  }
});

// ============================================================================
// POST /api/canvas/background-sync — BACKGROUND SYNC
// Triggered: 30-min interval (client-side) while authenticated and not in session.
// Also triggered at login if last_sync is within 14 days.
// Fetches only assignments due in next 14 days using due_after/due_before filters.
// ============================================================================
app.post('/api/canvas/background-sync', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log(`\n=== BACKGROUND SYNC START for user ${userId} ===`);

    // Get Canvas token
    const userResult = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv, last_sync FROM users WHERE id = $1',
      [userId]
    );
    const userRow = userResult.rows[0];
    if (!userRow?.canvas_api_token) {
      return res.json({ shouldSync: false, reason: 'no_token' });
    }
    const canvasToken = getDecryptedCanvasToken(userId, userRow);
    if (!canvasToken) return res.json({ shouldSync: false, reason: 'decrypt_failed' });

    const headers = { Authorization: `Bearer ${canvasToken}`, Accept: 'application/json' };

    // Fetch active courses first
    let courses;
    try {
      const resp = await axios.get(
        `${CANVAS_API_BASE}/courses?per_page=100`,
        { headers, timeout: 15000 }
      );
      courses = (resp.data || []).filter(c => {
        const enrollmentState = c.enrollments?.[0]?.enrollment_state;
        return !enrollmentState || enrollmentState === 'active' || enrollmentState === 'invited';
      });
    } catch (err) {
      console.warn('[BG SYNC] Failed to fetch courses:', err.message);
      return res.status(500).json({ error: 'Failed to fetch courses', details: err.message });
    }

    // 14-day window
    const now = new Date();
    const fourteenDaysOut = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);
    const dueAfter = now.toISOString();
    const dueBefore = fourteenDaysOut.toISOString();

    // updated_since: use last_sync if available, otherwise 24h ago as safe fallback
    const updatedSince = userRow.last_sync
      ? new Date(userRow.last_sync).toISOString()
      : new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();

    console.log(`[BG SYNC] Window: ${dueAfter} → ${dueBefore} | updated_since: ${updatedSince}`);

    const courseResults = await Promise.all(
      courses.map(async (course) => {
        try {
          const resp = await axios.get(
            `${CANVAS_API_BASE}/courses/${course.id}/assignments?include[]=submission&per_page=100&bucket=upcoming&updated_since=${encodeURIComponent(updatedSince)}`,
            { headers, timeout: 15000 }
          );
          const all = Array.isArray(resp.data) ? resp.data : [];
          return all
            .filter(a => {
              const effectiveDue = a.due_at || a.lock_at;
              if (!effectiveDue) return false;
              const d = new Date(effectiveDue);
              return d >= now && d <= fourteenDaysOut;
            })
            .map(a => ({ ...a, course_name: course.name, course_id: course.id }));
        } catch (err) {
          console.warn(`  [BG SYNC] Failed ${course.name}: ${err.message}`);
          return [];
        }
      })
    );
    const allAssignments = courseResults.flat();
    console.log(`[BG SYNC] ${allAssignments.length} assignments in 14-day window`);

    // Estimate times
    const tasks = [];
    for (const a of allAssignments) {
      const effectiveDue = a.due_at || a.lock_at;   // lock_at fallback for old quizzes
      const dueDate = new Date(effectiveDue);
      const isoStr = dueDate.toISOString();
      const sub = a.submission || {};
      const isSubmitted = sub.workflow_state === 'submitted' || sub.workflow_state === 'graded';

      const existingEst = await pool.query(
        'SELECT estimated_time FROM tasks WHERE user_id = $1 AND assignment_id = $2 LIMIT 1',
        [userId, a.id]
      );
      let estimatedTime;
      if (existingEst.rows.length > 0 && existingEst.rows[0].estimated_time != null) {
        estimatedTime = existingEst.rows[0].estimated_time;
      } else {
        estimatedTime = await estimateTaskTime({
          title: a.name, class: a.course_name, url: buildAssignmentUrl(a, a.course_id),
          assignmentId: a.id, courseId: a.course_id,
          pointsPossible: a.points_possible, gradingType: a.grading_type,
          description: a.description || ''
        }, userId);
      }

      tasks.push({
        title: a.name, segment: null, class: a.course_name,
        description: a.description || '', url: buildAssignmentUrl(a, a.course_id),
        deadlineDate: isoStr.split('T')[0], deadlineTime: isoStr.split('T')[1].split('.')[0],
        estimatedTime, courseId: a.course_id, assignmentId: a.id,
        quizId: a.quiz_id ?? null,             // classic quiz ID (null for non-quiz assignments)
        pointsPossible: a.points_possible ?? null, assignmentGroupId: a.assignment_group_id ?? null,
        currentScore: sub.score ?? null, currentGrade: sub.grade ? String(sub.grade).slice(0, 50) : null,
        gradingType: (a.grading_type || 'points').slice(0, 50),
        unlockAt: a.unlock_at ?? null, lockAt: a.lock_at ?? null,
        submittedAt: sub.submitted_at ?? null,
        isMissing: sub.missing ?? false, isLate: sub.late ?? false,
        completed: isSubmitted
      });
    }

    console.log(`[BG SYNC] Returning ${tasks.length} tasks`);
    res.json({ tasks, stats: { courses: courses.length, assignments: tasks.length } });

  } catch (err) {
    console.error('[BG SYNC] Error:', err.message);
    res.status(500).json({ error: 'Background sync failed', details: err.message });
  }
});

// ============================================================================
// POST /api/canvas/course-sync — COURSE SYNC
// Triggered: opening Marks page, opening Goals pane, 60-min silent interval.
// ============================================================================
app.post('/api/canvas/course-sync', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log(`\n=== COURSE SYNC for user ${userId} ===`);

    // Get Canvas token
    const userResult = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv FROM users WHERE id = $1',
      [userId]
    );
    const canvasToken = getDecryptedCanvasToken(userId, userResult.rows[0]);
    if (!canvasToken) {
      return res.status(400).json({ error: 'No Canvas API token found.' });
    }
    const headers = { Authorization: `Bearer ${canvasToken}`, Accept: 'application/json' };

    // Fetch courses WITH grade data
    console.log('[COURSE SYNC] Fetching courses with grades...');
    let courses;
    try {
      const resp = await axios.get(
        `${CANVAS_API_BASE}/courses?include[]=total_scores&include[]=current_grading_period_scores&per_page=100`,
        { headers, timeout: 15000 }
      );
      // Filter out courses where the user's own enrollment is concluded/inactive.
      // Without enrollment_state=active, Canvas returns all-time enrollments; we only
      // want courses the student is currently attending (active or invited), not archived
      // courses from prior years.
      courses = (resp.data || []).filter(c => {
        const enrollmentState = c.enrollments?.[0]?.enrollment_state;
        return !enrollmentState || enrollmentState === 'active' || enrollmentState === 'invited';
      });
      console.log(`[COURSE SYNC] ${courses.length} courses fetched (after enrollment filter)`);
    } catch (err) {
      if (err.response?.status === 401) {
        return res.status(400).json({ error: 'Canvas token invalid or expired. Please update your token in Settings.' });
      }
      return res.status(500).json({ error: 'Failed to fetch courses', details: err.message });
    }

    // Upsert courses
    for (const course of courses) {
      const enrollment = course.enrollments?.[0] || {};
      await pool.query(
        `INSERT INTO courses (user_id, course_id, name, course_code, current_score, current_grade,
           final_score, final_grade, enrollment_id, current_period_score, current_period_grade,
           grading_period_id, grading_period_title, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CURRENT_TIMESTAMP)
         ON CONFLICT (user_id, course_id) DO UPDATE SET
           name=EXCLUDED.name, course_code=EXCLUDED.course_code,
           current_score=EXCLUDED.current_score, current_grade=EXCLUDED.current_grade,
           final_score=EXCLUDED.final_score, final_grade=EXCLUDED.final_grade,
           current_period_score=EXCLUDED.current_period_score,
           current_period_grade=EXCLUDED.current_period_grade,
           grading_period_id=EXCLUDED.grading_period_id,
           grading_period_title=EXCLUDED.grading_period_title,
           updated_at=CURRENT_TIMESTAMP`,
        [userId, course.id, course.name, course.course_code ?? null,
         enrollment.computed_current_score ?? enrollment.grades?.current_score ?? null,
         enrollment.computed_current_grade ?? enrollment.grades?.current_grade ?? null,
         enrollment.computed_final_score ?? enrollment.grades?.final_score ?? null,
         enrollment.computed_final_grade ?? enrollment.grades?.final_grade ?? null,
         enrollment.id ?? null,
         enrollment.current_period_computed_current_score ?? null,
         enrollment.current_period_computed_current_grade ?? null,
         enrollment.current_grading_period_id ?? null,
         enrollment.current_grading_period_title ?? null]
      );
    }

    // Auto-link: if any newly upserted course matches a 'course'-type studio, ensure
    // the hpt_studio_members table is NOT involved (course studios derive live), but
    // for 'key'-type studios we still don't auto-add. Log for diagnostics only.
    try {
      const courseIds = courses.map(c => c.id);
      if (courseIds.length > 0) {
        const linked = await pool.query(
          `SELECT s.id, s.name FROM hpt_studios s WHERE s.setup_type='course' AND s.course_id = ANY($1::bigint[])`,
          [courseIds]
        );
        if (linked.rows.length > 0) {
          console.log(`[COURSE SYNC] User ${userId} linked to ${linked.rows.length} HPT studio(s) via course_id`);
        }
      }
    } catch (linkErr) {
      console.warn('[COURSE SYNC] Studio auto-link check failed (non-fatal):', linkErr.message);
    }

    // Fetch assignment groups IN PARALLEL
    console.log('[COURSE SYNC] Fetching assignment groups in parallel...');
    await Promise.all(
      courses.map(async (course) => {
        try {
          const resp = await axios.get(
            `${CANVAS_API_BASE}/courses/${course.id}/assignment_groups`,
            { headers, timeout: 10000 }
          );
          for (const group of resp.data) {
            await pool.query(
              `INSERT INTO assignment_groups (user_id, course_id, group_id, name, weight, updated_at)
               VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP)
               ON CONFLICT (user_id, course_id, group_id)
               DO UPDATE SET name=EXCLUDED.name, weight=EXCLUDED.weight, updated_at=CURRENT_TIMESTAMP`,
              [userId, course.id, group.id, group.name, group.group_weight ?? null]
            );
          }
          console.log(`  [COURSE SYNC] ${course.name}: ${resp.data.length} assignment groups`);
        } catch (err) {
          console.warn(`  [COURSE SYNC] Assignment groups failed for ${course.name}: ${err.message}`);
        }
      })
    );

    console.log(`[COURSE SYNC] Complete: ${courses.length} courses synced`);
    res.json({ success: true, courses: courses.length });

  } catch (err) {
    console.error('[COURSE SYNC] Error:', err.message);
    res.status(500).json({ error: 'Course sync failed', details: err.message });
  }
});

// ============================================================================
// POST /api/canvas/grade-sync — GRADE SYNC
// Triggered: opening Activity pane on Account & Analytics page.
// Fetches graded submissions within the last 2 months for all enrolled courses.
// Upserts into grade_history keyed by (user_id, assignment_id):
//   - First-run users: unread=FALSE (prevent historical flood on signup)
//   - Returning users: new rows get unread=TRUE; score changes flip existing rows to unread=TRUE
app.post('/api/canvas/grade-sync', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log(`\n=== GRADE SYNC for user ${userId} ===`);

    // Step 1: Check and decrypt Canvas token
    const userResult = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv FROM users WHERE id = $1',
      [userId]
    );
    const canvasToken = getDecryptedCanvasToken(userId, userResult.rows[0]);
    if (!canvasToken) return res.status(400).json({ error: 'No Canvas API token found.' });

    const headers = { Authorization: `Bearer ${canvasToken}` };

    // First-run guard: if grade_history is empty for this user, mark all incoming
    // grades as unread=FALSE to avoid flooding the notification sidebar on first load.
    const existingGradeCount = await pool.query(
      'SELECT 1 FROM grade_history WHERE user_id=$1 LIMIT 1', [userId]
    );
    const isFirstRun = existingGradeCount.rows.length === 0;

    // Step 2: Get all enrolled course IDs from the courses table.
    const coursesRes = await pool.query(
      'SELECT DISTINCT course_id FROM courses WHERE user_id = $1 AND enabled = true',
      [userId]
    );
    const courseIds = coursesRes.rows.map(r => r.course_id);
    if (courseIds.length === 0) {
      console.log('[GRADE SYNC] No enrolled courses found.');
      return res.json({ updated: 0, total: 0 });
    }
    console.log(`[GRADE SYNC] Fetching submissions for ${courseIds.length} course(s)`);

    // 2-month window: only process grades from the last 2 months
    const twoMonthsAgo = new Date();
    twoMonthsAgo.setMonth(twoMonthsAgo.getMonth() - 2);

    // Step 3: Fetch graded submissions for each course in parallel.
    const submissionResults = await Promise.allSettled(
      courseIds.map(cid =>
        axios.get(
          `${CANVAS_API_BASE}/courses/${cid}/students/submissions?student_ids[]=self&include[]=assignment&per_page=100`,
          { headers, timeout: 15000 }
        ).then(r => r.data.map(s => ({ ...s, _courseId: cid })))
         .catch(err => {
           console.warn(`[GRADE SYNC] Course ${cid} fetch failed: ${err.message}`);
           return [];
         })
      )
    );
    const allSubs = submissionResults.flatMap(r => r.status === 'fulfilled' ? r.value : []);
    console.log(`[GRADE SYNC] Total submissions fetched: ${allSubs.length}`);

    // Step 4: Build course_id → course_name lookup
    const courseNameRes = await pool.query(
      'SELECT course_id, name FROM courses WHERE user_id = $1',
      [userId]
    );
    const courseNameMap = {};
    courseNameRes.rows.forEach(r => { courseNameMap[r.course_id] = r.name; });

    // Step 5: Upsert each graded submission into grade_history.
    // Window: skip anything graded/submitted more than 2 months ago.
    // unread logic: new rows → unread=TRUE (unless first run); score changes on
    // existing rows → flip unread back to TRUE so the user sees the update.
    let upsertedCount = 0;
    for (const sub of allSubs) {
      if (sub.score == null && !sub.grade) continue;

      const assignment = sub.assignment || {};
      // graded_at from Canvas; fall back to submitted_at
      const gradedAt = sub.graded_at || sub.submitted_at || null;
      if (gradedAt && new Date(gradedAt) < twoMonthsAgo) continue;

      const title        = assignment.name || `Assignment ${sub.assignment_id}`;
      const courseName   = courseNameMap[sub._courseId] || null;
      const htmlUrl      = assignment.html_url || sub.preview_url || null;
      const pointsPoss   = assignment.points_possible != null ? parseFloat(assignment.points_possible) : null;
      const score        = sub.score != null ? parseFloat(sub.score) : null;
      const grade        = sub.grade || null;
      const gradingType  = assignment.grading_type || 'points';
      const submittedAt  = sub.submitted_at || null;

      // Check if the row already exists and if the score changed
      const existing = await pool.query(
        'SELECT id, score, grade FROM grade_history WHERE user_id=$1 AND assignment_id=$2',
        [userId, sub.assignment_id]
      );

      if (existing.rows.length > 0) {
        // Compare as floats to avoid false positives from DB returning "91.00" vs JS 91
        const existingScore = existing.rows[0].score != null ? parseFloat(existing.rows[0].score) : null;
        const scoreChanged = existingScore !== score; // both are null or parseFloat
        const gradeChanged = existing.rows[0].grade !== grade;
        const changed = scoreChanged || gradeChanged;
        await pool.query(
          `UPDATE grade_history SET
             title=$1, course_name=$2, html_url=$3, score=$4, points_possible=$5,
             grade=$6, grading_type=$7, submitted_at=$8, graded_at=$9, synced_at=NOW(),
             unread = CASE WHEN $10 THEN true ELSE unread END
           WHERE user_id=$11 AND assignment_id=$12`,
          [title, courseName, htmlUrl, score, pointsPoss,
           grade, gradingType, submittedAt, gradedAt,
           changed && !isFirstRun,
           userId, sub.assignment_id]
        );
      } else {
        await pool.query(
          `INSERT INTO grade_history
             (user_id, course_id, assignment_id, title, course_name, html_url,
              score, points_possible, grade, grading_type, submitted_at, graded_at, synced_at, unread)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),$13)`,
          [userId, sub._courseId, sub.assignment_id, title, courseName, htmlUrl,
           score, pointsPoss, grade, gradingType, submittedAt, gradedAt,
           !isFirstRun] // unread=FALSE for first-run users
        );
      }
      upsertedCount++;
    }

    console.log(`[GRADE SYNC] Complete: ${upsertedCount} grades upserted`);
    res.json({ updated: upsertedCount, total: allSubs.length });

  } catch (err) {
    console.error('[GRADE SYNC] Error:', err.message);
    res.status(500).json({ error: 'Grade sync failed', details: err.message });
  }
});

// ============================================================================
// PRIORITY ORDER CLEANUP - No-op stub kept for call-site compatibility.
// priority_order column has been removed; tasks are always sorted by deadline.
// ============================================================================

async function reprioritizeTasks(userId, pool) {
  // priority_order removed — tasks are ordered by deadline_date / deadline_time.
  // This stub is intentionally empty; all callers remain unchanged.
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
      `SELECT AVG(
         CASE
           WHEN current_period_score IS NOT NULL AND current_period_score::text ~ '^[0-9]+(\\.[0-9]+)?$'
             THEN current_period_score::numeric
           WHEN current_score IS NOT NULL AND current_score::text ~ '^[0-9]+(\\.[0-9]+)?$'
             THEN current_score::numeric
           ELSE NULL
         END
       ) as avg_score, COUNT(DISTINCT user_id) as student_count
       FROM courses
       WHERE course_id = $1
         AND enabled = true`,
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

// GET /api/tasks/grade-impact — returns { task_id: 'Low'|'Moderate'|'High' } for tasks with points_possible
// Requires ≥10 tasks globally with same course_id + assignment_group_id. Uses group weight from assignment_groups.
app.get('/api/tasks/grade-impact', authenticateToken, async (req, res) => {
  try {
    const userTasksResult = await pool.query(
      `SELECT id, course_id, assignment_group_id, points_possible
       FROM tasks
       WHERE user_id = $1
         AND deleted = false
         AND completed = false
         AND points_possible IS NOT NULL
         AND points_possible > 0
         AND course_id IS NOT NULL
         AND assignment_group_id IS NOT NULL`,
      [req.user.id]
    );
    if (userTasksResult.rows.length === 0) return res.json({});

    const combos = [...new Set(userTasksResult.rows.map(r => `${r.course_id}:${r.assignment_group_id}`))];
    const comboStats = {};
    for (const combo of combos) {
      const [courseId, groupId] = combo.split(':');
      const statsResult = await pool.query(
        `SELECT COUNT(*) as task_count, AVG(points_possible) as avg_points
         FROM tasks
         WHERE course_id = $1 AND assignment_group_id = $2
           AND points_possible IS NOT NULL AND points_possible > 0`,
        [courseId, groupId]
      );
      const count = parseInt(statsResult.rows[0].task_count) || 0;
      const avg = parseFloat(statsResult.rows[0].avg_points) || 0;
      if (count >= 10 && avg > 0) {
        const weightResult = await pool.query(
          `SELECT weight FROM assignment_groups
           WHERE course_id = $1 AND group_id = $2 AND weight IS NOT NULL LIMIT 1`,
          [courseId, groupId]
        );
        const weight = weightResult.rows[0]?.weight ?? 100;
        comboStats[combo] = { avg, count, weight };
      }
    }

    const impactMap = {};
    for (const task of userTasksResult.rows) {
      const combo = `${task.course_id}:${task.assignment_group_id}`;
      const stats = comboStats[combo];
      if (!stats) continue;

      // ratio: how large this task is relative to the average for its group
      // A ratio of 1.0 = exactly average. >1 = larger than average. <1 = smaller.
      const ratio = parseFloat(task.points_possible) / stats.avg;

      // Weight factor: high-weight groups (e.g. 40%) lower the thresholds so
      // average-sized tasks in important groups still rank Moderate/High.
      // Low-weight groups (e.g. 5%) raise the thresholds — only outsized tasks rank up.
      // Normalised around 25% as the baseline (typical assignment group weight).
      const weightFactor = 25 / Math.max(stats.weight, 5);

      // Thresholds scaled by weightFactor:
      //   25%-weight group: Low < 0.75, Moderate 0.75–1.5, High > 1.5
      //   40%-weight group: Low < 0.47, Moderate 0.47–0.94, High > 0.94 (easier to rank up)
      //   10%-weight group: Low < 1.88, Moderate 1.88–3.75, High > 3.75 (harder to rank up)
      const lowThreshold = 0.75 * weightFactor;
      const highThreshold = 1.5 * weightFactor;

      let rank;
      if (ratio < lowThreshold) rank = 'Low';
      else if (ratio < highThreshold) rank = 'Moderate';
      else rank = 'High';
      impactMap[task.id] = rank;
    }
    res.json(impactMap);
  } catch (error) {
    console.error('Grade impact error:', error);
    res.status(500).json({ error: 'Failed to calculate grade impact' });
  }
});

// GET /api/goals — fetch all goals for the current user as { course_id: target_score }
app.get('/api/goals', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT course_id, target_score FROM user_goals WHERE user_id = $1',
      [req.user.id]
    );
    const goalsMap = {};
    for (const row of result.rows) goalsMap[String(row.course_id)] = parseFloat(row.target_score);
    res.json(goalsMap);
  } catch (error) {
    console.error('Get goals error:', error);
    res.status(500).json({ error: 'Failed to get goals' });
  }
});

// POST /api/goals — save/update all goals. Body: { goals: { course_id: target_score } }
app.post('/api/goals', authenticateToken, async (req, res) => {
  try {
    const { goals } = req.body;
    if (!goals || typeof goals !== 'object') return res.status(400).json({ error: 'goals must be an object' });
    for (const [courseId, score] of Object.entries(goals)) {
      const n = parseFloat(score);
      if (isNaN(n) || n < 45 || n > 100) return res.status(400).json({ error: `Invalid score ${score} for course ${courseId}` });
    }
    for (const [courseId, score] of Object.entries(goals)) {
      await pool.query(
        `INSERT INTO user_goals (user_id, course_id, target_score, updated_at)
         VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
         ON CONFLICT (user_id, course_id)
         DO UPDATE SET target_score = $3, updated_at = CURRENT_TIMESTAMP`,
        [req.user.id, courseId, parseFloat(score)]
      );
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Save goals error:', error);
    res.status(500).json({ error: 'Failed to save goals' });
  }
});

// DELETE /api/goals — discard all goals for the current user
app.delete('/api/goals', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM user_goals WHERE user_id = $1', [req.user.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete goals error:', error);
    res.status(500).json({ error: 'Failed to delete goals' });
  }
});

// ============================================================================
// TASK MANAGEMENT ROUTES
// ============================================================================

// GET /api/canvas/check-completed/:taskId — check if Canvas has marked this task submitted
app.get('/api/canvas/check-completed/:taskId', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const taskResult = await pool.query(
      'SELECT assignment_id, quiz_id, course_id, canvas_api_token, canvas_api_token_iv FROM tasks t JOIN users u ON u.id = t.user_id WHERE t.id = $1 AND t.user_id = $2',
      [taskId, req.user.id]
    );
    if (taskResult.rows.length === 0) return res.json({ completed: false });
    const task = taskResult.rows[0];
    if (!task.course_id) return res.json({ completed: false });
    if (!task.canvas_api_token || !task.canvas_api_token_iv) return res.json({ completed: false });
    const encParts = task.canvas_api_token.split(':');
    if (encParts.length < 2) return res.json({ completed: false });
    const token = decryptToken(encParts[0], task.canvas_api_token_iv, encParts[1]);
    const authHeader = { Authorization: `Bearer ${token}` };

    // Old-style Canvas quizzes (quiz_id present): use quiz submission endpoint.
    // New-style assignments: use the standard assignments/submissions/self endpoint.
    if (task.quiz_id) {
      try {
        const subResp = await axios.get(
          `${CANVAS_API_BASE}/courses/${task.course_id}/quizzes/${task.quiz_id}/submission`,
          { headers: authHeader, timeout: 8000 }
        );
        // Canvas returns quiz_submissions array; a submitted quiz has workflow_state = 'complete'
        const submissions = subResp.data?.quiz_submissions ?? [];
        const latest = submissions[0];
        const done = latest?.workflow_state === 'complete' || latest?.workflow_state === 'pending_review';
        return res.json({ completed: done });
      } catch (err) {
        const status = err.response?.status;
        if (status === 401 || status === 403 || status === 404) {
          return res.json({ completed: false });
        }
        // Unexpected error — fall through to try the assignment endpoint as a backstop
      }
    }

    // Standard assignment submission check
    if (!task.assignment_id) return res.json({ completed: false });
    const subResp = await axios.get(
      `${CANVAS_API_BASE}/courses/${task.course_id}/assignments/${task.assignment_id}/submissions/self`,
      { headers: authHeader, timeout: 8000 }
    );
    const wf = subResp.data?.workflow_state;
    res.json({ completed: wf === 'submitted' || wf === 'graded' });
  } catch (err) {
    const status = err.response?.status;
    // 401: Canvas token expired/invalid; 403: assignment type doesn't support submissions/self
    // (e.g. external tools); 404: assignment deleted/archived on Canvas.
    if (status === 401 || status === 403 || status === 404) {
      return res.json({ completed: false });
    }
    console.error('Canvas check-completed error:', err.message);
    res.json({ completed: false });
  }
});

// POST /api/canvas/auto-sync — DEPRECATED: kept for backward compat, frontend now calls /canvas/background-sync
// Returns shouldSync=true if Canvas token exists
app.post('/api/canvas/auto-sync', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT canvas_api_token FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!userResult.rows[0]?.canvas_api_token) {
      return res.json({ shouldSync: false, reason: 'no_token' });
    }
    res.json({ shouldSync: true });
  } catch (err) {
    console.error('Auto-sync check error:', err);
    res.json({ shouldSync: false });
  }
});


// Get tasks (all incomplete tasks)
// Calendar endpoint - returns ALL non-deleted tasks (including completed)
// plus tasks_completed entries, merged for the calendar view
app.get('/api/tasks/calendar', authenticateToken, async (req, res) => {
  try {
    // Active + completed tasks still in tasks table (deleted=false)
    const activeResult = await pool.query(
      `SELECT id, title, segment, class, url, description,
              deadline_date, deadline_time,
              completed, submitted_at, is_missing, is_late,
              points_possible, course_id, assignment_id
       FROM tasks
       WHERE user_id = $1 AND deleted = false AND (inactive = false OR inactive IS NULL)
       ORDER BY deadline_date ASC, deadline_time ASC NULLS LAST`,
      [req.user.id]
    );

    // Tasks completed via sessions (hard-deleted from tasks, moved to tasks_completed)
    // Only fetch within a reasonable window (30 days back, 30 days forward)
    const completedResult = await pool.query(
      `SELECT id, title, NULL as segment, class, url, NULL as description,
              deadline_date,
              deadline_time,
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
         AND (inactive = false OR inactive IS NULL)
       ORDER BY deadline_date ASC, deadline_time ASC NULLS LAST, segment ASC NULLS FIRST`,
      [req.user.id]
    );
    res.json(result.rows || []);
  } catch (error) {
    console.error('Get tasks error:', error);
    res.json([]);
  }
});

// Save & Adjust Plan — lightweight endpoint that only updates segment,
// user_estimated_time, and accumulated_time for existing tasks.
app.post('/api/tasks/save-plan', authenticateToken, async (req, res) => {
  try {
    const { tasks } = req.body;
    if (!Array.isArray(tasks)) {
      return res.status(400).json({ error: 'Tasks must be an array' });
    }

    console.log(`\n=== SAVE PLAN: Updating ${tasks.length} tasks for user ${req.user.id} ===`);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const task of tasks) {
        if (!task.id) continue;
        await client.query(
          `UPDATE tasks
           SET segment            = $1,
               user_estimated_time = $2,
               accumulated_time   = $3
           WHERE id = $4 AND user_id = $5`,
          [
            task.segment ?? null,
            task.userEstimate ?? null,
            task.accumulatedTime ?? 0,
            task.id,
            req.user.id
          ]
        );
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    console.log(`=== SAVE PLAN COMPLETE ===`);
    res.json({ success: true });
  } catch (error) {
    console.error('Save plan error:', error);
    res.status(500).json({ error: 'Failed to save plan' });
  }
});

// Save tasks (bulk import from Canvas)
// ============================================================================
// POST /api/tasks/sync-save — Shared batched upsert for Main Sync + Background Sync
// partial=true → skip global soft-delete cleanup (Background Sync only sends a 14-day window)
//                but ALWAYS soft-delete tasks past their deadline
// ============================================================================
app.post('/api/tasks/sync-save', authenticateToken, async (req, res) => {
  try {
    const { tasks, partial = false, syncType = 'main' } = req.body;
    if (!Array.isArray(tasks)) return res.status(400).json({ error: 'tasks must be an array' });

    const userId = req.user.id;
    console.log(`\n=== SYNC-SAVE [${syncType}] partial=${partial}: ${tasks.length} tasks for user ${userId} ===`);

    // ── Step 1: Batch-load all existing tasks for this user by assignment_id + url ──
    const assignmentIds = tasks.map(t => t.assignmentId).filter(Boolean);
    const urls = tasks.map(t => t.url).filter(Boolean);

    const [byAssignmentId, byUrl] = await Promise.all([
      assignmentIds.length > 0
        ? pool.query(
            'SELECT * FROM tasks WHERE user_id = $1 AND assignment_id = ANY($2)',
            [userId, assignmentIds]
          )
        : Promise.resolve({ rows: [] }),
      urls.length > 0
        ? pool.query(
            'SELECT * FROM tasks WHERE user_id = $1 AND url = ANY($2)',
            [userId, urls]
          )
        : Promise.resolve({ rows: [] })
    ]);

    // Build lookup maps
    const byAssId = new Map();
    byAssignmentId.rows.forEach(r => byAssId.set(String(r.assignment_id), r));
    const byUrlMap = new Map();
    byUrl.rows.forEach(r => {
      if (!byUrlMap.has(r.url)) byUrlMap.set(r.url, []);
      byUrlMap.get(r.url).push(r);
    });

    // ── Step 2: Pre-fetch max grade_id ──
    const gradeIdRes = await pool.query(
      'SELECT COALESCE(MAX(grade_id), 0) AS max_id FROM tasks WHERE user_id = $1',
      [userId]
    );
    let nextGradeId = parseInt(gradeIdRes.rows[0].max_id) + 1;

    const sortedTasks = [...tasks].sort((a, b) => {
      const dA = new Date(`${a.deadlineDate}T${a.deadlineTime || '23:59:59'}Z`);
      const dB = new Date(`${b.deadlineDate}T${b.deadlineTime || '23:59:59'}Z`);
      return dA - dB;
    });

    let updatedCount = 0, newCount = 0, completionFlips = 0;
    const insertedTaskIds = [];

    // ── Step 3: Upsert each task ──
    for (const t of sortedTasks) {
      // Find existing record
      let existing = (t.assignmentId && byAssId.get(String(t.assignmentId))) ||
                     (t.url && (byUrlMap.get(t.url) || []).find(r => !r.segment)) ||
                     null;

      const isSubmitted = t.completed === true ||
        t.submittedAt != null ||
        t.isMissing === false; // Canvas submission present

      if (existing) {
        if (existing.manually_created) {
          console.log(`  [SKIP] Manually created: "${existing.title}"`);
          insertedTaskIds.push(existing.id);
          continue;
        }

        // Detect completed=FALSE→TRUE flip (Canvas submission detected)
        const wasCompleted = existing.completed;
        const nowCompleted = t.completed === true;
        const completionFlip = !wasCompleted && nowCompleted;

        // Detect grade change — compare as floats to avoid false positives from
        // DB returning "50.00" (NUMERIC string) while Canvas sends 50 (JS number).
        const existingScore = existing.current_score != null ? parseFloat(existing.current_score) : null;
        const incomingScore = t.currentScore != null ? parseFloat(t.currentScore) : null;
        const scoreChanged = incomingScore != null && incomingScore !== existingScore;
        const gradeChanged = t.currentGrade != null && t.currentGrade !== existing.current_grade;
        const gradeFlipped = (scoreChanged || gradeChanged) && !existing.segment;
        let gradeIdToUse = existing.grade_id;
        if (gradeFlipped) {
          gradeIdToUse = nextGradeId++;
        }

        if (existing.segment) {
          // Segment task: only update display fields
          await pool.query(
            `UPDATE tasks SET title=$1, class=$2, url=$3, deadline_date=$4, deadline_time=$5,
               points_possible=$6, current_score=$7, current_grade=$8,
               submitted_at=$9, is_missing=$10, is_late=$11
             WHERE id=$12 AND user_id=$13`,
            [t.title, t.class, t.url, t.deadlineDate, t.deadlineTime,
             t.pointsPossible ?? null, t.currentScore ?? null, t.currentGrade ?? null,
             t.submittedAt ?? null, t.isMissing ?? false, t.isLate ?? false,
             existing.id, userId]
          );
        } else {
          // Full canvas field update
          await pool.query(
            `UPDATE tasks SET
               title=$1, class=$2, description=$3, url=$4,
               deadline_date=$5, deadline_time=$6, course_id=$7, assignment_id=$8,
               quiz_id=$9, points_possible=$10, assignment_group_id=$11,
               current_score=$12, current_grade=$13, grading_type=$14,
               unlock_at=$15, lock_at=$16, submitted_at=$17,
               is_missing=$18, is_late=$19, grade_id=$20,
               completed=$21, deleted=CASE WHEN $21 THEN true ELSE deleted END
             WHERE id=$22 AND user_id=$23`,
            [t.title, t.class, t.description || '', t.url,
             t.deadlineDate, t.deadlineTime, t.courseId ?? null, t.assignmentId ?? null,
             t.quizId ?? null, t.pointsPossible ?? null, t.assignmentGroupId ?? null,
             t.currentScore ?? null, t.currentGrade ?? null, t.gradingType || 'points',
             t.unlockAt ?? null, t.lockAt ?? null, t.submittedAt ?? null,
             t.isMissing ?? false, t.isLate ?? false, gradeIdToUse,
             nowCompleted, existing.id, userId]
          );
        }

        if (completionFlip) {
          completionFlips++;
          console.log(`  ★ Completion flip detected for "${existing.title}" → updating leaderboard + feed`);
          incrementLeaderboardForUser(userId).catch(err =>
            console.error('[LEADERBOARD] sync flip error:', err.message));
          addToCompletionFeed(userId, existing.title, existing.class).catch(err =>
            console.error('[FEED] sync flip error:', err.message));
        }
        if (gradeFlipped) {
          console.log(`  ★ Grade change for "${existing.title}": ${existing.current_score}→${t.currentScore} (grade_id=${gradeIdToUse})`);
        }
        updatedCount++;
        insertedTaskIds.push(existing.id);

      } else {
        // ── INSERT new task ──
        const result = await pool.query(
          `INSERT INTO tasks
             (user_id, title, segment, class, description, url,
              deadline_date, deadline_time, estimated_time, user_estimated_time,
              course_id, assignment_id, quiz_id, points_possible, assignment_group_id,
              current_score, current_grade, grading_type,
              unlock_at, lock_at, submitted_at, is_missing, is_late,
              completed, deleted, manually_created, is_new)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
           RETURNING id`,
          [userId, t.title, t.segment ?? null, t.class, t.description || '', t.url,
           t.deadlineDate, t.deadlineTime, t.estimatedTime, t.userEstimate ?? null,
           t.courseId ?? null, t.assignmentId ?? null, t.quizId ?? null,
           t.pointsPossible ?? null, t.assignmentGroupId ?? null,
           t.currentScore ?? null, t.currentGrade ?? null,
           t.gradingType || 'points', t.unlockAt ?? null, t.lockAt ?? null,
           t.submittedAt ?? null, t.isMissing ?? false, t.isLate ?? false,
           t.completed ?? false, t.completed ?? false, // deleted if already completed
           false, true] // manually_created=false, is_new=true
        );
        const newId = result.rows[0].id;
        insertedTaskIds.push(newId);
        newCount++;
        console.log(`  ✓ Inserted task ID ${newId}: "${t.title}"`);

        // Fire leaderboard + feed for tasks that arrive already completed this week.
        // These are tasks the student submitted before PlanAssist first synced them
        // (e.g. submitted immediately when published, or between two syncs).
        // Gate: completed=true AND either (a) submitted_at is within this calendar week,
        // or (b) no submitted_at but deadline is within this week.
        // We intentionally exclude old/historical completions (submitted months ago).
        if (t.completed === true) {
          const weekStart = new Date();
          weekStart.setHours(0, 0, 0, 0);
          weekStart.setDate(weekStart.getDate() - (weekStart.getDay() === 0 ? 6 : weekStart.getDay() - 1));
          const completionDate = t.submittedAt ? new Date(t.submittedAt)
            : (t.deadlineDate ? new Date(t.deadlineDate + 'T00:00:00') : null);
          const isThisWeek = completionDate && completionDate >= weekStart;
          if (isThisWeek) {
            console.log(`  ★ New task already completed this week: "${t.title}" → leaderboard + feed`);
            incrementLeaderboardForUser(userId).catch(err =>
              console.error('[LEADERBOARD] new-complete error:', err.message));
            addToCompletionFeed(userId, t.title, t.class).catch(err =>
              console.error('[FEED] new-complete error:', err.message));
          }
        }
      }
    }

    // ── Step 4: Soft-delete past-due incomplete tasks (always, even for partial) ──
    const nowUtc = new Date().toISOString().split('T')[0];
    const pastDueCleanup = await pool.query(
      `UPDATE tasks SET deleted=true, session_active=false
       WHERE user_id=$1 AND completed=false AND deleted=false AND deadline_date < $2
       RETURNING id, title`,
      [userId, nowUtc]
    );
    if (pastDueCleanup.rowCount > 0) {
      console.log(`[SYNC-SAVE] Soft-deleted ${pastDueCleanup.rowCount} past-due task(s)`);
    }

      // ── Step 4b: Mark inactive tasks (full sync only) ──
    // On a full (non-partial) sync the incoming list represents Canvas's complete
    // current state. Any non-completed, non-deleted Canvas task that was NOT in
    // the response was either unpublished or removed by the teacher. Mark it
    // inactive so it disappears from the UI without losing accumulated time.
    // Guard: only runs if the inactive column exists (pre-migration safety).
    let inactiveCount = 0;
    if (!partial) {
      try {
        const seenAssignmentIds = sortedTasks
          .map(t => t.assignmentId)
          .filter(id => id != null)
          .map(String);
        if (seenAssignmentIds.length > 0) {
          const inactiveResult = await pool.query(
            `UPDATE tasks SET inactive = true
             WHERE user_id = $1
               AND completed = false
               AND deleted = false
               AND (inactive = false OR inactive IS NULL)
               AND manually_created = false
               AND assignment_id IS NOT NULL
               AND assignment_id::text != ALL($2)
             RETURNING id, title`,
            [userId, seenAssignmentIds]
          );
          inactiveCount = inactiveResult.rowCount;
          if (inactiveCount > 0) {
            console.log(`[SYNC-SAVE] Marked ${inactiveCount} task(s) inactive (removed/unpublished from Canvas):`);
            inactiveResult.rows.forEach(t => console.log(`  - "${t.title}"`));
          }
        }
        // Re-activate tasks that re-appear in Canvas after being marked inactive
        if (insertedTaskIds.length > 0) {
          await pool.query(
            `UPDATE tasks SET inactive = false
             WHERE user_id = $1 AND id = ANY($2) AND inactive = true`,
            [userId, insertedTaskIds]
          );
        }
      } catch (inactiveErr) {
        // If the inactive column doesn't exist yet, skip silently
        if (!inactiveErr.message.includes('column "inactive"')) throw inactiveErr;
        console.warn('[SYNC-SAVE] inactive column not yet in DB — skipping inactive marking');
      }
    }

    // ── Step 5: Update last_sync timestamp ──
    await pool.query(
      'UPDATE users SET last_sync = CURRENT_TIMESTAMP WHERE id = $1',
      [userId]
    );

    console.log(`=== SYNC-SAVE COMPLETE: updated=${updatedCount} new=${newCount} leaderboard_flips=${completionFlips} past_due_cleaned=${pastDueCleanup.rowCount} inactive=${inactiveCount} ===`);

    res.json({
      success: true,
      stats: { updated: updatedCount, new: newCount, completionFlips, cleaned: pastDueCleanup.rowCount, inactive: inactiveCount }
    });
  } catch (err) {
    console.error('[SYNC-SAVE] Error:', err.message);
    console.error(err.stack);
    res.status(500).json({ error: 'Failed to save tasks', details: err.message });
  }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { tasks } = req.body;

    if (!Array.isArray(tasks)) {
      return res.status(400).json({ error: 'Tasks must be an array' });
    }

    console.log(`\n=== SYNC OPERATION: Processing ${tasks.length} tasks from Canvas API ===`);

    // CRITICAL: Sort tasks by deadline before assigning priorities
    // Sort tasks by deadline — earliest first
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

    // Pre-fetch max grade_id once to avoid race conditions when multiple
    // grade changes are detected in the same sync — increment locally
    const gradeIdBaseResult = await pool.query(
      'SELECT COALESCE(MAX(grade_id), 0) AS max_id FROM tasks WHERE user_id = $1',
      [req.user.id]
    );
    let nextGradeId = parseInt(gradeIdBaseResult.rows[0].max_id) + 1;

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
          let segChanged = false;
          let taskChanged = false;
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
              // Only update if something actually changed
              segChanged =
                existingTask.title !== incomingTask.title ||
                existingTask.class !== incomingTask.class ||
                (existingTask.deadline_date || '').toString().slice(0,10) !== (incomingTask.deadlineDate || '') ||
                (existingTask.current_score != null ? parseFloat(existingTask.current_score) : null) !== (incomingTask.currentScore != null ? parseFloat(incomingTask.currentScore) : null) ||
                (existingTask.current_grade ?? null) !== (incomingTask.currentGrade ?? null) ||
                (existingTask.submitted_at ?? null) !== (incomingTask.submittedAt ?? null) ||
                (existingTask.is_missing ?? false) !== (incomingTask.isMissing ?? false) ||
                (existingTask.is_late ?? false) !== (incomingTask.isLate ?? false) ||
                false; // ignored flag removed
              if (segChanged) {
                await pool.query(
                  `UPDATE tasks SET \
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
              }
            } else {
              // Non-segment task: full canvas field update
              // Only update if something actually changed
              taskChanged =
                existingTask.title !== incomingTask.title ||
                existingTask.class !== incomingTask.class ||
                (existingTask.deadline_date || '').toString().slice(0,10) !== (incomingTask.deadlineDate || '') ||
                existingTask.completed !== (incomingTask.completed ?? false) ||
                (existingTask.current_score != null ? parseFloat(existingTask.current_score) : null) !== (incomingTask.currentScore != null ? parseFloat(incomingTask.currentScore) : null) ||
                (existingTask.current_grade ?? null) !== (incomingTask.currentGrade ?? null) ||
                (existingTask.submitted_at ?? null) !== (incomingTask.submittedAt ?? null) ||
                (existingTask.is_missing ?? false) !== (incomingTask.isMissing ?? false) ||
                (existingTask.is_late ?? false) !== (incomingTask.isLate ?? false) ||
                false; // ignored flag removed
              if (taskChanged) {
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
            (incomingTask.currentScore != null ? parseFloat(incomingTask.currentScore) : null) !==
            (existingTask.current_score != null ? parseFloat(existingTask.current_score) : null);
          const gradeChanged = incomingTask.currentGrade != null &&
            incomingTask.currentGrade !== existingTask.current_grade;
          if (hasCanvasData && (scoreChanged || gradeChanged)) {
            await pool.query(
              'UPDATE tasks SET grade_id = $1 WHERE id = $2 AND user_id = $3',
              [nextGradeId, existingTask.id, req.user.id]
            );
            console.log(`  ★ Grade change detected for task ${existingTask.id}, assigned grade_id=${nextGradeId}`);
            nextGradeId++;
          }

          // If Canvas now marks the task completed and it wasn't before:
          if (!existingTask.segment && incomingTask.completed && !existingTask.completed) {
            // Only write tasks_completed if user hasn't manually resolved it already
            if (!existingTask.deleted) {
              await pool.query(
                `INSERT INTO tasks_completed (id, user_id, title, class, description, url, deadline_date, deadline_time, estimated_time, actual_time, completed_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)
                 ON CONFLICT (id) DO NOTHING`,
                [
                  existingTask.id, req.user.id, existingTask.title, existingTask.class,
                  existingTask.description || '', existingTask.url,
                  existingTask.deadline_date, existingTask.deadline_time,
                  existingTask.user_estimated_time || existingTask.estimated_time,
                  existingTask.accumulated_time || 0
                ]
              );
              console.log(`  ★ Canvas-completed task ${existingTask.id}: wrote tasks_completed row`);
            }
            // Leaderboard fires regardless of deleted status — student submitted on Canvas
            updateLeaderboardOnCompletion(req.user.id).catch(err => console.error('Sync leaderboard update failed:', err));
            console.log(`  ★ Leaderboard updated for task ${existingTask.id} (Canvas completed flip)`);
          }

          // If task was previously dismissed (deleted=true), treat it as a new task for sidebar/count purposes
          {
            const didChange = existingTask.segment ? segChanged : taskChanged;
            if (didChange) {
              console.log(`  ✓ Updated task ID ${existingTask.id}: "${existingTask.title}"`);
              updatedCount++;
            } else {
              console.log(`  — No change: task ID ${existingTask.id}: "${existingTask.title}"`);
            }
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
        
        const isAlreadyCompleted = incomingTask.completed ?? false;

        const result = await pool.query(
          `INSERT INTO tasks 
           (user_id, title, segment, class, description, url, deadline_date, deadline_time, estimated_time, user_estimated_time, accumulated_time, completed, deleted,
            course_id, assignment_id, quiz_id, points_possible, assignment_group_id, current_score, current_grade, grading_type, unlock_at, lock_at, submitted_at, is_missing, is_late)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
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
             quiz_id = EXCLUDED.quiz_id,
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
            incomingTask.completed ?? false,
            false, // Not deleted
            incomingTask.courseId ?? null,
            incomingTask.assignmentId ?? null,
            incomingTask.quizId ?? null,
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
        console.log(`  ✓ Created task ID ${result.rows[0].id}`);
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
          `UPDATE tasks SET deleted = true
           WHERE user_id = $1
             AND deleted = false
             AND course_id = ANY($2::int[])
             AND deadline_date <= $3`,
          [req.user.id, disabledCourseIds, tenDaysAgo.toISOString().slice(0, 10)]
        );

        // Recent tasks: just ignore (don't delete, not old enough)
        const ignoreRecent = await pool.query(
          `UPDATE tasks SET deleted = true
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
      `UPDATE tasks SET deleted = true
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

    res.json({ 
      success: true, 
      tasks: insertedTasks, 
      stats: { 
        updated: updatedCount, 
        new: newCount,
        cleaned: cleanedUpCount,
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
          estimated_time, user_estimated_time, accumulated_time, completed,
          course_id, assignment_id, points_possible, assignment_group_id, grading_type,
          deleted, manually_created)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                 $13, NULL, NULL, NULL, 'points', false, false)
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
          segAccumulatedTime,
          false,
          originalTask.course_id   // keep course association, but NO assignment_id
        ]
      );
      
      newSegments.push(result.rows[0]);
    }

    // Soft-delete the original task so Sync doesn't re-import it as a new task
    // The Sync will find the segments by assignment_id and update them
    await pool.query(
      'UPDATE tasks SET deleted = true, split_origin = true, session_active = false WHERE id = $1 AND user_id = $2',
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
// POST /api/tasks/reorder — kept for backwards-compat; tasks are now deadline-sorted
app.post('/api/tasks/reorder', authenticateToken, async (req, res) => {
  // priority_order removed; tasks always sort by deadline. This is a safe no-op.
  res.json({ success: true });
});



// POST /api/tasks/sort-by-deadline — no-op; tasks are always deadline-sorted now.
app.post('/api/tasks/sort-by-deadline', authenticateToken, async (req, res) => {
  res.json({ success: true });
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

    // Mark task completed and deleted.
    // completed=true must be set so sync-save's wasCompleted check sees it
    // and does not re-fire the leaderboard increment on the next sync.
    await pool.query(
      'UPDATE tasks SET completed = true, deleted = true, session_active = false WHERE id = $1 AND user_id = $2',
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

    await pool.query(
      'UPDATE tasks SET deleted = false WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
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
              points_possible, assignment_id, course_id, manually_created
       FROM tasks
       WHERE user_id = $1
         AND completed = false
         AND deleted = false
         AND (inactive = false OR inactive IS NULL)
         AND LOWER(class) NOT LIKE '%homeroom%'
       ORDER BY deadline_date ASC, deadline_time ASC NULLS LAST, segment ASC NULLS FIRST`,
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

// POST /api/sessions/pause/:taskId — save elapsed time (session_active stays true — user is still in the session)
app.post('/api/sessions/pause/:taskId', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { accumulatedTime } = req.body;
    await pool.query(
      'UPDATE tasks SET accumulated_time = $1 WHERE id = $2 AND user_id = $3',
      [accumulatedTime, taskId, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Pause session error:', error);
    res.status(500).json({ error: 'Failed to pause session' });
  }
});

// POST /api/sessions/end/:taskId — user exits session back to Sessions page, clear active flag
app.post('/api/sessions/end/:taskId', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { accumulatedTime } = req.body;
    // Update accumulated time for the specific task
    await pool.query(
      'UPDATE tasks SET accumulated_time = $1 WHERE id = $2 AND user_id = $3',
      [accumulatedTime ?? 0, taskId, req.user.id]
    );
    // Clear session_active for ALL tasks belonging to this user (belt-and-suspenders)
    await pool.query(
      'UPDATE tasks SET session_active = false WHERE user_id = $1 AND session_active = true',
      [req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('End session error:', error);
    res.status(500).json({ error: 'Failed to end session' });
  }
});

// POST /api/sessions/agenda-start/:taskId — mark task active when agenda row is entered
app.post('/api/sessions/agenda-start/:taskId', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    // Clear any other active sessions first
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
    console.error('Agenda start error:', error);
    res.status(500).json({ error: 'Failed to set agenda session active' });
  }
});

// POST /api/sessions/agenda-end/:taskId — clear active flag when leaving agenda
app.post('/api/sessions/agenda-end/:taskId', authenticateToken, async (req, res) => {
  try {
    // Clear session_active for ALL tasks belonging to this user (belt-and-suspenders)
    await pool.query(
      'UPDATE tasks SET session_active = false WHERE user_id = $1 AND session_active = true',
      [req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Agenda end error:', error);
    res.status(500).json({ error: 'Failed to clear agenda session active' });
  }
});

// POST /api/sessions/heartbeat — called every 30s while a timer is running.
// Writes a fresh timestamp to session_heartbeat on the active task so the admin
// panel can distinguish a genuinely live session from a stale session_active flag.
app.post('/api/sessions/heartbeat', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      `UPDATE tasks SET session_heartbeat = NOW()
       WHERE user_id = $1 AND session_active = true`,
      [req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Heartbeat error:', error);
    res.status(500).json({ error: 'Failed to write heartbeat' });
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
      // Task may have already been completed/deleted — treat as success
      return res.json({ success: true, alreadyCompleted: true });
    }
    
    const task = taskResult.rows[0];

    // If already completed, just return success (idempotent)
    if (task.completed || task.deleted) {
      return res.json({ success: true, alreadyCompleted: true });
    }

    // Only write to tasks_completed if actual time was logged (timeSpent > 0)
    // If timeSpent is 0 or absent, skip the tasks_completed entry — task is
    // marked done but no time record is created (avoids polluting analytics)
    const hasTimeToLog = timeSpent && timeSpent > 0;
    
    // For segment tasks: check if another segment of the same task already exists
    // in tasks_completed. If so, merge by accumulating estimated_time + actual_time.
    // Always fire leaderboard + feed regardless (each segment is real work done).
    if (hasTimeToLog && task.segment && task.url) {
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
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)
           ON CONFLICT (id) DO UPDATE SET
             actual_time = COALESCE(EXCLUDED.actual_time, tasks_completed.actual_time),
             completed_at = CURRENT_TIMESTAMP`,
          [
            task.id, req.user.id, task.title, task.class, task.description, task.url,
            task.deadline_date, task.deadline_time,
            task.user_estimated_time || task.estimated_time,
            timeSpent
          ]
        );
      }
    } else if (hasTimeToLog) {
      // Non-segment task: upsert — safe if already completed via another path
      await pool.query(
        `INSERT INTO tasks_completed (id, user_id, title, class, description, url, deadline_date, deadline_time, estimated_time, actual_time, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)
         ON CONFLICT (id) DO UPDATE SET
           actual_time = COALESCE(EXCLUDED.actual_time, tasks_completed.actual_time),
           completed_at = CURRENT_TIMESTAMP`,
        [
          task.id, req.user.id, task.title, task.class, task.description, task.url,
          task.deadline_date, task.deadline_time,
          task.user_estimated_time || task.estimated_time,
          timeSpent
        ]
      );
    }
    
    // Mark task as completed AND deleted.
    // Setting completed=true is critical: sync-save checks existing.completed before
    // firing the leaderboard increment. If completed stays false, every subsequent sync
    // that sees Canvas has it submitted will re-fire the leaderboard (double-count).
    await pool.query(
      'UPDATE tasks SET completed = true, deleted = true, session_active = false WHERE id = $1 AND user_id = $2',
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
      // Feed: only Canvas tasks done in Session/Agenda with time > 0
      addToCompletionFeed(req.user.id, task.title, task.class, {
        manuallyCreated: task.manually_created || false,
        timeSpent: timeSpent || 0
      }).catch(err => console.error('Feed update failed:', err));

      // Leaderboard: only if Canvas has confirmed the submission (canvasCompleted=true)
      // and the task was NOT already completed before this action (task.completed was FALSE)
      // This matches the spec: check completed=FALSE in DB first, then Canvas confirms.
      const { canvasCompleted } = req.body;
      if (canvasCompleted === true) {
        console.log(`[MARK COMPLETE] Canvas confirmed submission for task ${taskId} — updating leaderboard`);
        incrementLeaderboardForUser(req.user.id).catch(err =>
          console.error('[LEADERBOARD] Mark complete error:', err.message));
      }
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Complete task error:', error);
    res.status(500).json({ error: 'Failed to complete task' });
  }
});

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
    
    // Mark task as deleted — stays in DB so it won't be re-imported on sync.
    // Viewable in the Activity > Resolutions tab.
    await pool.query(
      'UPDATE tasks SET deleted = true WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    console.log(`✓ Task ${taskId} dismissed by user ${req.user.id}`);
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
// STREAK SHIELDS
// ============================================================================

// GET /api/streak/data — single endpoint that returns all data needed for client-side streak calc.
// Returns campus, shields, shield mode, all completion timestamps, and all shield consumed_at timestamps.
// The client converts ALL timestamps (completions and shields) from UTC → campus-tz dates.
// Per spec: consumed_at is the UTC timestamp of when the shield was used; its campus-tz date
// is the day that gets covered in the streak. shield_date is not used for streak calculations.
app.get('/api/streak/data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const userR = await pool.query(
      'SELECT campus, streak_shields_available, streak_shield_mode FROM users WHERE id = $1',
      [userId]
    );
    const row = userR.rows[0] || {};

    // All completion timestamps (UTC) — client converts to campus-tz dates
    const completionsR = await pool.query(
      'SELECT completed_at FROM tasks_completed WHERE user_id = $1 ORDER BY completed_at ASC',
      [userId]
    );

    // Shield consumed_at timestamps (UTC) — client converts to campus-tz dates.
    // The campus-tz date of consumed_at is the day the shield covers, per spec.
    const shieldsR = await pool.query(
      'SELECT consumed_at FROM streak_shield_log WHERE user_id = $1 ORDER BY consumed_at ASC',
      [userId]
    );

    res.json({
      campus:           row.campus ?? 'Ashland',
      shieldsAvailable: row.streak_shields_available ?? 0,
      shieldMode:       row.streak_shield_mode ?? 'manual',
      completedAt: completionsR.rows.map(r =>
        r.completed_at instanceof Date ? r.completed_at.toISOString() : String(r.completed_at)
      ),
      // consumed_at is a TIMESTAMP — return as UTC ISO strings, same as completedAt
      consumedAt: shieldsR.rows.map(r =>
        r.consumed_at instanceof Date ? r.consumed_at.toISOString() : String(r.consumed_at)
      ),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/streak/shields — get user's shield count and mode
app.get('/api/streak/shields', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT streak_shields_available, streak_shield_mode FROM users WHERE id = $1',
      [req.user.id]
    );
    res.json({ available: r.rows[0]?.streak_shields_available ?? 0, mode: r.rows[0]?.streak_shield_mode ?? 'manual' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/streak/shields/use — manually consume one shield for a specific date
app.post('/api/streak/shields/use', authenticateToken, async (req, res) => {
  try {
    const { date } = req.body; // YYYY-MM-DD campus-tz date to shield
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Invalid date' });
    const user = await pool.query('SELECT streak_shields_available, campus FROM users WHERE id = $1', [req.user.id]);
    if ((user.rows[0]?.streak_shields_available ?? 0) < 1) return res.status(400).json({ error: 'No shields available' });
    // Compute consumed_at as noon on the campus-tz date, converted to UTC.
    // This ensures toCampusDate(consumed_at) always yields back the correct campus date.
    const campus = user.rows[0]?.campus || 'Ashland';
    const consumedAt = campusDateToUTC(date, campus);
    await pool.query('BEGIN');
    const ins = await pool.query(
      'INSERT INTO streak_shield_log (user_id, shield_date, consumed_at) VALUES ($1, $2, $3) ON CONFLICT (user_id, shield_date) DO NOTHING RETURNING shield_date',
      [req.user.id, date, consumedAt]
    );
    if (ins.rowCount === 0) {
      await pool.query('COMMIT');
      const cur = await pool.query('SELECT streak_shields_available FROM users WHERE id = $1', [req.user.id]);
      return res.json({ success: true, alreadyShielded: true, shieldedDate: date, remaining: cur.rows[0].streak_shields_available });
    }
    await pool.query(
      'UPDATE users SET streak_shields_available = streak_shields_available - 1 WHERE id = $1 AND streak_shields_available > 0',
      [req.user.id]
    );
    await pool.query('COMMIT');
    const updated = await pool.query('SELECT streak_shields_available FROM users WHERE id = $1', [req.user.id]);
    res.json({ success: true, alreadyShielded: false, shieldedDate: date, remaining: updated.rows[0].streak_shields_available });
  } catch (err) { await pool.query('ROLLBACK').catch(() => {}); res.status(500).json({ error: err.message }); }
});

// POST /api/streak/shields/auto-consume — consume shields for gap dates (automatic mode)
app.post('/api/streak/shields/auto-consume', authenticateToken, async (req, res) => {
  try {
    const { gapDates } = req.body; // array of YYYY-MM-DD campus-tz strings
    if (!Array.isArray(gapDates) || gapDates.length === 0) return res.json({ consumed: 0 });
    const user = await pool.query('SELECT streak_shields_available, campus FROM users WHERE id = $1', [req.user.id]);
    let available = user.rows[0]?.streak_shields_available ?? 0;
    const campus = user.rows[0]?.campus || 'Ashland';
    let consumed = 0;
    await pool.query('BEGIN');
    for (const date of gapDates) {
      if (available <= 0) break;
      // Set consumed_at to noon on the campus-tz gap date, converted to UTC,
      // so that toCampusDate(consumed_at) always yields the correct campus date.
      const consumedAt = campusDateToUTC(date, campus);
      const ins = await pool.query(
        'INSERT INTO streak_shield_log (user_id, shield_date, consumed_at) VALUES ($1, $2, $3) ON CONFLICT (user_id, shield_date) DO NOTHING RETURNING id',
        [req.user.id, date, consumedAt]
      );
      if (ins.rowCount > 0) { available--; consumed++; }
    }
    if (consumed > 0) {
      await pool.query(
        'UPDATE users SET streak_shields_available = streak_shields_available - $1 WHERE id = $2',
        [consumed, req.user.id]
      );
    }
    await pool.query('COMMIT');
    res.json({ consumed, remaining: available });
  } catch (err) { await pool.query('ROLLBACK').catch(() => {}); res.status(500).json({ error: err.message }); }
});

// PUT /api/streak/shields/mode — toggle manual/automatic
app.put('/api/streak/shields/mode', authenticateToken, async (req, res) => {
  try {
    const { mode } = req.body;
    if (!['manual', 'automatic'].includes(mode)) return res.status(400).json({ error: 'Invalid mode' });
    await pool.query('UPDATE users SET streak_shield_mode = $1 WHERE id = $2', [mode, req.user.id]);
    res.json({ success: true, mode });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/streak/shields/log — get shield usage log for streak calculation
app.get('/api/streak/shields/log', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT shield_date FROM streak_shield_log WHERE user_id = $1 ORDER BY shield_date DESC',
      [req.user.id]
    );
    res.json({ shieldDates: r.rows.map(row => row.shield_date) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/streak/records — get personal record and all-time record
app.get('/api/streak/records', authenticateToken, async (req, res) => {
  try {
    // We compute streaks client-side; the server just returns the needed raw data
    // For the all-time record across all users we'd need all completion dates — instead,
    // store a high-water mark column. For now return max streak from weekly_leaderboard proxy.
    // A dedicated max_streak column on users is cleaner — return null for now (client computes).
    res.json({ note: 'Computed client-side from completion history' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================================
// FEED REACTIONS
// ============================================================================

// GET /api/feed-reactions/:entryId — get reactions for a feed entry
app.get('/api/feed-reactions/:entryId', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT fr.emoji, COUNT(*) as count,
              bool_or(fr.user_id = $1) as user_reacted,
              (SELECT fr2.emoji FROM feed_reactions fr2 WHERE fr2.feed_entry_id = $2 AND fr2.user_id = $1 LIMIT 1) as user_emoji
       FROM feed_reactions fr
       WHERE fr.feed_entry_id = $2
       GROUP BY fr.emoji
       ORDER BY count DESC`,
      [req.user.id, req.params.entryId]
    );
    res.json({ reactions: r.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/feed-reactions/:entryId — add or replace reaction
app.post('/api/feed-reactions/:entryId', authenticateToken, async (req, res) => {
  try {
    const { emoji } = req.body;
    if (!emoji) return res.status(400).json({ error: 'emoji required' });
    await pool.query(
      `INSERT INTO feed_reactions (feed_entry_id, user_id, emoji)
       VALUES ($1, $2, $3)
       ON CONFLICT (feed_entry_id, user_id) DO UPDATE SET emoji = EXCLUDED.emoji, created_at = CURRENT_TIMESTAMP`,
      [req.params.entryId, req.user.id, emoji]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/feed-reactions/:entryId — remove own reaction
app.delete('/api/feed-reactions/:entryId', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM feed_reactions WHERE feed_entry_id = $1 AND user_id = $2',
      [req.params.entryId, req.user.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================================
// INSIGNIA
// ============================================================================

// GET /api/insignia — get current insignia, days count, and all unlocked insignias
app.get('/api/insignia', authenticateToken, async (req, res) => {
  try {
    // Compute distinct completion days dynamically from tasks_completed so the counter
    // is always accurate even if insignia_days was never incremented for historical entries.
    const daysR = await pool.query(
      'SELECT COUNT(DISTINCT completed_at::date) AS days FROM tasks_completed WHERE user_id = $1',
      [req.user.id]
    );
    const computedDays = parseInt(daysR.rows[0]?.days ?? 0);

    // Keep the stored insignia_days column in sync (catches any drift from the counter approach)
    await pool.query(
      'UPDATE users SET insignia_days = $1 WHERE id = $2 AND insignia_days != $1',
      [computedDays, req.user.id]
    );

    const userR = await pool.query(
      'SELECT insignia_selected FROM users WHERE id = $1', [req.user.id]
    );
    const unlocksR = await pool.query(
      'SELECT label, unlocked_at FROM insignia_unlocks WHERE user_id = $1 ORDER BY unlocked_at ASC', [req.user.id]
    );
    res.json({
      days: computedDays,
      selected: userR.rows[0]?.insignia_selected ?? 'Default',
      unlocked: unlocksR.rows
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/insignia — set selected insignia
app.put('/api/insignia', authenticateToken, async (req, res) => {
  try {
    const { label } = req.body;
    // Whitelist guard — only known tier names are accepted
    const VALID_INSIGNIA = ['Default','Copper','Silver','Gold','Emerald',
                            'Amethyst','Ruby','Diamond','Obsidian','Antimatter'];
    if (!VALID_INSIGNIA.includes(label)) {
      return res.status(400).json({ error: 'Invalid insignia label' });
    }
    // Verify user has unlocked this label
    const check = await pool.query(
      'SELECT 1 FROM insignia_unlocks WHERE user_id = $1 AND label = $2', [req.user.id, label]
    );
    if (check.rowCount === 0) return res.status(403).json({ error: 'Label not unlocked' });
    await pool.query('UPDATE users SET insignia_selected = $1 WHERE id = $2', [label, req.user.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/insignia/check-unlock — check if new insignias were unlocked after a completion
// Called by sync-save/mark-complete when insignia_days may have changed
app.post('/api/insignia/check-unlock', authenticateToken, async (req, res) => {
  try {
    const INSIGNIA_THRESHOLDS = [
      [0,'Default'],[2,'Copper'],[5,'Silver'],[10,'Gold'],[20,'Emerald'],
      [30,'Amethyst'],[40,'Ruby'],[50,'Diamond'],[75,'Obsidian'],[100,'Antimatter']
    ];
    // Compute dynamically from tasks_completed (same approach as GET /api/insignia)
    const daysR = await pool.query(
      'SELECT COUNT(DISTINCT completed_at::date) AS days FROM tasks_completed WHERE user_id = $1',
      [req.user.id]
    );
    const days = parseInt(daysR.rows[0]?.days ?? 0);
    // Keep stored value in sync
    await pool.query(
      'UPDATE users SET insignia_days = $1 WHERE id = $2 AND insignia_days != $1',
      [days, req.user.id]
    );
    const newlyUnlocked = [];
    for (const [threshold, label] of INSIGNIA_THRESHOLDS) {
      if (days >= threshold) {
        const ins = await pool.query(
          'INSERT INTO insignia_unlocks (user_id, label, unread) VALUES ($1, $2, true) ON CONFLICT DO NOTHING RETURNING label',
          [req.user.id, label]
        ).catch(() =>
          pool.query('INSERT INTO insignia_unlocks (user_id, label) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING label', [req.user.id, label])
        );
        if (ins.rowCount > 0) newlyUnlocked.push(label);
      }
    }
    res.json({ newlyUnlocked, days });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================================
// GALLERY BADGES
// ============================================================================

// GET /api/badges — get all earned badges for the user
app.get('/api/badges', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT badge_key, awarded_at FROM user_badges WHERE user_id = $1 ORDER BY awarded_at ASC',
      [req.user.id]
    );
    res.json({ badges: r.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/badges/check — check and award any new badges (called on Hub load)
app.post('/api/badges/check', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const newBadges = [];

    // Helper: award badge if not already awarded
    const award = async (key, awardedAt) => {
      const r = await pool.query(
        'INSERT INTO user_badges (user_id, badge_key, awarded_at, unread) VALUES ($1,$2,$3,true) ON CONFLICT DO NOTHING RETURNING badge_key',
        [userId, key, awardedAt || new Date()]
      ).catch(() =>
        pool.query('INSERT INTO user_badges (user_id, badge_key, awarded_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING badge_key', [userId, key, awardedAt || new Date()])
      );
      if (r.rowCount > 0) newBadges.push(key);
    };

    // Total completions milestones
    const totalR = await pool.query(
      'SELECT COUNT(*) as cnt, MIN(completed_at) as first_at FROM tasks_completed WHERE user_id = $1', [userId]
    );
    const total = parseInt(totalR.rows[0].cnt);
    const firstAt = totalR.rows[0].first_at;
    if (total >= 1) await award('first_completion', firstAt);
    for (const t of [10,25,50,100,250,500]) {
      if (total >= t) {
        const atR = await pool.query(
          'SELECT completed_at FROM tasks_completed WHERE user_id = $1 ORDER BY completed_at ASC LIMIT $2',
          [userId, t]
        );
        const rows = atR.rows;
        if (rows.length >= t) await award('tasks_' + t, rows[rows.length - 1].completed_at);
      }
    }

    // Most tasks in a single day
    const dayR = await pool.query(
      `SELECT completed_at::date AS day, COUNT(*) AS cnt
       FROM tasks_completed WHERE user_id = $1
       GROUP BY completed_at::date ORDER BY cnt DESC LIMIT 1`,
      [userId]
    );
    if (dayR.rows.length > 0) {
      const best = parseInt(dayR.rows[0].cnt);
      const bestDay = dayR.rows[0].day;
      for (const t of [3,5,10,20]) {
        if (best >= t) await award('day_' + t, bestDay);
      }
    }

    // Streak badges — use the highest of current streak and personal record so badges
    // earned during a past streak are never lost when the current streak is lower.
    const { currentStreak, personalRecord } = req.body;
    const bestStreak = Math.max(parseInt(currentStreak) || 0, parseInt(personalRecord) || 0);
    if (bestStreak > 0) {
      for (const t of [7,14,30,60,100]) {
        if (bestStreak >= t) await award('streak_' + t);
      }
    }

    // Early bird: completed a task before 8am
    const earlyR = await pool.query(
      `SELECT completed_at FROM tasks_completed WHERE user_id = $1
       AND EXTRACT(HOUR FROM completed_at AT TIME ZONE 'UTC') < 8 LIMIT 1`,
      [userId]
    );
    if (earlyR.rows.length > 0) await award('early_bird', earlyR.rows[0].completed_at);

    // Night owl: completed a task after 10pm
    const nightR = await pool.query(
      `SELECT completed_at FROM tasks_completed WHERE user_id = $1
       AND EXTRACT(HOUR FROM completed_at AT TIME ZONE 'UTC') >= 22 LIMIT 1`,
      [userId]
    );
    if (nightR.rows.length > 0) await award('night_owl', nightR.rows[0].completed_at);

    res.json({ newBadges });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================================
// ADMIN: Streak shield grants
// ============================================================================

// ============================================================================
// HUB FEATURES - Completion Feed & Leaderboard
// ============================================================================

// Get recent completion feed (last 30 completions from opted-in users)
app.get('/api/completion-feed', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT cf.id, cf.user_name, cf.user_grade, cf.task_title, cf.task_class, cf.completed_at,
              COALESCE(u.insignia_selected, 'Default') AS insignia,
              COALESCE(
                (SELECT json_agg(json_build_object('emoji', fr.emoji, 'count', fr.cnt))
                 FROM (SELECT emoji, COUNT(*) AS cnt FROM feed_reactions WHERE feed_entry_id = cf.id GROUP BY emoji) fr),
                '[]'::json
              ) AS reactions,
              (SELECT fr2.emoji FROM feed_reactions fr2 WHERE fr2.feed_entry_id = cf.id AND fr2.user_id = $1 LIMIT 1) AS user_reaction
       FROM completion_feed cf
       JOIN users u ON cf.user_id = u.id
       WHERE u.show_in_feed = true
       AND cf.completed_at > NOW() - INTERVAL '14 days'
       ORDER BY cf.completed_at DESC
       LIMIT 30`,
      [req.user.id]
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
    
    // Get top 10 for this grade this week, join with users for insignia
    const result = await pool.query(
      `SELECT wl.user_name, wl.grade, wl.tasks_completed, wl.updated_at,
              COALESCE(u.insignia_selected, 'Default') AS insignia
       FROM weekly_leaderboard wl
       LEFT JOIN users u ON u.id = wl.user_id
       WHERE wl.grade = $1 AND wl.week_start = $2
       ORDER BY wl.tasks_completed DESC, wl.updated_at ASC
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
// ── Shared: update leaderboard when sync detects a Canvas submission flip ──────
// Called by Main Sync, Background Sync, and the Mark Complete endpoint.
// Only increments weekly_leaderboard.tasks_completed — no tasks_completed write.
async function incrementLeaderboardForUser(userId) {
  try {
    const userResult = await pool.query(
      'SELECT name, grade FROM users WHERE id = $1',
      [userId]
    );
    if (userResult.rows.length === 0) return;
    const user = userResult.rows[0];
    const weekStartRes = await pool.query(
      `SELECT DATE_TRUNC('week', CURRENT_DATE)::date AS week_start`
    );
    const weekStart = weekStartRes.rows[0].week_start;
    await pool.query(
      `INSERT INTO weekly_leaderboard (user_id, user_name, grade, tasks_completed, week_start, updated_at)
       VALUES ($1, $2, $3, 1, $4, CURRENT_TIMESTAMP)
       ON CONFLICT (user_id, week_start)
       DO UPDATE SET tasks_completed = weekly_leaderboard.tasks_completed + 1,
                     updated_at = CURRENT_TIMESTAMP`,
      [userId, user.name, user.grade, weekStart]
    );
    console.log(`[LEADERBOARD] Incremented tasks_completed for user ${userId} (week ${weekStart})`);
  } catch (err) {
    console.error('[LEADERBOARD] incrementLeaderboardForUser error:', err.message);
  }
}

async function updateLeaderboardOnCompletion(userId) {
  try {
    // Get user info
    const userResult = await pool.query(
      'SELECT name, grade, show_in_feed, insignia_selected FROM users WHERE id = $1',
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
async function addToCompletionFeed(userId, taskTitle, taskClass, { manuallyCreated = false, timeSpent = 0 } = {}) {
  try {
    // ── Always increment insignia_days on the first completion of each UTC day ──
    // This runs regardless of feed opt-in, manual creation, or time spent,
    // so insignia_days reliably reflects every day the user completes ≥1 task.
    const todayUtc = new Date().toISOString().slice(0, 10);
    const alreadyTodayRes = await pool.query(
      `SELECT 1 FROM tasks_completed
       WHERE user_id = $1 AND completed_at::date = $2::date LIMIT 1`,
      [userId, todayUtc]
    );
    if (alreadyTodayRes.rowCount === 0) {
      await pool.query(
        'UPDATE users SET insignia_days = insignia_days + 1 WHERE id = $1',
        [userId]
      );
      console.log(`[INSIGNIA] Incremented insignia_days for user ${userId}`);
    }

    // ── Feed entry: only Canvas tasks completed with time > 0 ──
    // Feed rule: only Canvas tasks (not manually created) completed with time > 0
    if (manuallyCreated || !(timeSpent > 0)) return;

    // Get user info
    const userResult = await pool.query(
      'SELECT name, grade, show_in_feed, insignia_selected FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0 || !userResult.rows[0].show_in_feed) return;

    const user = userResult.rows[0];

    // Add to completion feed
    await pool.query(
      `INSERT INTO completion_feed (user_id, user_name, user_grade, task_title, task_class, completed_at, insignia)
       VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6)`,
      [userId, user.name, user.grade, taskTitle, taskClass, user.insignia_selected || 'Default']
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
// GET /api/agendas — list active agendas with hydrated row task data
app.get('/api/agendas', authenticateToken, async (req, res) => {
  try {
    const agendasResult = await pool.query(
      `SELECT id, name, rows, current_row, current_row_elapsed, current_row_countdown,
              finished, created_at
       FROM agendas
       WHERE user_id = $1 AND finished = false
       ORDER BY created_at ASC`,
      [req.user.id]
    );

    const agendas = await Promise.all(agendasResult.rows.map(async (agenda) => {
      const rows = agenda.rows || [];
      const taskIds = [...new Set(rows.map(r => r.taskId).filter(Boolean))];
      if (taskIds.length === 0) {
        // No tasks at all — delete this agenda
        await pool.query('DELETE FROM agendas WHERE id = $1 AND user_id = $2', [agenda.id, req.user.id]);
        return null;
      }

      const tasksResult = await pool.query(
        `SELECT id, title, segment, class, url, deadline_date, deadline_time,
                estimated_time, user_estimated_time, accumulated_time,
                session_active, completed, deleted
         FROM tasks WHERE id = ANY($1) AND user_id = $2`,
        [taskIds, req.user.id]
      );
      const taskMap = {};
      tasksResult.rows.forEach(t => { taskMap[t.id] = t; });

      // Strip rows whose task is gone, completed, or deleted
      const validRows = rows.filter(r => {
        const t = taskMap[r.taskId];
        return t && !t.completed && !t.deleted;
      });

      // If all rows wiped out, delete the agenda entirely
      if (validRows.length === 0) {
        await pool.query('DELETE FROM agendas WHERE id = $1 AND user_id = $2', [agenda.id, req.user.id]);
        return null;
      }

      // Re-index rowIndex values after any removals
      const reindexed = validRows.map((r, i) => ({ ...r, rowIndex: i }));

      // Clamp current_row to new length
      const newCurrentRow = Math.min(agenda.current_row || 0, reindexed.length - 1);
      const rowsChanged = reindexed.length !== rows.length || newCurrentRow !== (agenda.current_row || 0);
      if (rowsChanged) {
        await pool.query(
          'UPDATE agendas SET rows = $1, current_row = $2, updated_at = NOW() WHERE id = $3 AND user_id = $4',
          [JSON.stringify(reindexed), newCurrentRow, agenda.id, req.user.id]
        );
      }

      const hydratedRows = reindexed.map(r => ({
        ...r,
        task: taskMap[r.taskId] || null
      }));

      return { ...agenda, rows: hydratedRows, current_row: newCurrentRow };
    }));

    res.json(agendas.filter(a => a !== null));
  } catch (error) {
    console.error('Get agendas error:', error);
    res.status(500).json({ error: 'Failed to get agendas' });
  }
});

// POST /api/agendas — create a new agenda
app.post('/api/agendas', authenticateToken, async (req, res) => {
  try {
    const { name, rows } = req.body;
    if (!name || !Array.isArray(rows) || rows.length === 0 || rows.length > 10) {
      return res.status(400).json({ error: 'Name and 1–10 rows are required' });
    }

    // Normalise rows: enforce schema, default action, clamp timeMins
    const VALID_ZONES = ['focus', 'semi', 'collab'];
    const cleanRows = rows.map((r, i) => ({
      rowIndex: i,
      taskId: r.taskId,
      action: (r.action || '').trim().slice(0, 100) || 'Work on Task',
      timeMins: Math.max(1, parseInt(r.timeMins) || 25),
      zone: VALID_ZONES.includes(r.zone) ? r.zone : null,
    }));

    const result = await pool.query(
      `INSERT INTO agendas (user_id, name, rows)
       VALUES ($1, $2, $3)
       RETURNING id, name, rows, current_row, current_row_elapsed, current_row_countdown, finished, created_at`,
      [req.user.id, name.trim(), JSON.stringify(cleanRows)]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Create agenda error:', error);
    res.status(500).json({ error: 'Failed to create agenda' });
  }
});

// PATCH /api/agendas/:agendaId/rows — edit future rows (current_row+1 and beyond only)
app.patch('/api/agendas/:agendaId/rows', authenticateToken, async (req, res) => {
  try {
    const { agendaId } = req.params;
    const { rows } = req.body;

    const agendaResult = await pool.query(
      'SELECT rows, current_row FROM agendas WHERE id = $1 AND user_id = $2',
      [agendaId, req.user.id]
    );
    if (agendaResult.rows.length === 0) return res.status(404).json({ error: 'Agenda not found' });

    const existing = agendaResult.rows[0];
    const lockedRows = (existing.rows || []).filter(r => r.rowIndex <= existing.current_row);

    // Incoming rows must only be for indices > current_row
    const editableIncoming = (rows || []).filter(r => r.rowIndex > existing.current_row);
    if (lockedRows.length + editableIncoming.length > 10) {
      return res.status(400).json({ error: 'Cannot exceed 10 rows' });
    }

    const VALID_ZONES = ['focus', 'semi', 'collab'];
    const cleanEditable = editableIncoming.map((r, i) => ({
      rowIndex: lockedRows.length + i,
      taskId: r.taskId,
      action: (r.action || '').trim().slice(0, 100) || 'Work on Task',
      timeMins: Math.max(1, parseInt(r.timeMins) || 25),
      zone: VALID_ZONES.includes(r.zone) ? r.zone : null,
    }));

    const merged = [...lockedRows, ...cleanEditable];

    await pool.query(
      'UPDATE agendas SET rows = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3',
      [JSON.stringify(merged), agendaId, req.user.id]
    );
    res.json({ success: true, rows: merged });
  } catch (error) {
    console.error('Edit agenda rows error:', error);
    res.status(500).json({ error: 'Failed to update agenda rows' });
  }
});

// POST /api/agendas/:agendaId/proceed — save progress and advance to next row
app.post('/api/agendas/:agendaId/proceed', authenticateToken, async (req, res) => {
  try {
    const { agendaId } = req.params;
    const { taskId, elapsedSeconds } = req.body;

    const agendaResult = await pool.query(
      'SELECT rows, current_row FROM agendas WHERE id = $1 AND user_id = $2',
      [agendaId, req.user.id]
    );
    if (agendaResult.rows.length === 0) return res.status(404).json({ error: 'Agenda not found' });

    const { rows, current_row } = agendaResult.rows[0];
    const nextRow = current_row + 1;
    const isLastRow = nextRow >= rows.length;

    // Save accumulated time for the task
    if (taskId && elapsedSeconds > 0) {
      const mins = Math.round(elapsedSeconds / 60);
      await pool.query(
        `UPDATE tasks SET accumulated_time = COALESCE(accumulated_time, 0) + $1
         WHERE id = $2 AND user_id = $3`,
        [mins, taskId, req.user.id]
      );
    }

    if (isLastRow) {
      // Last row proceeded — mark finished
      await pool.query(
        `UPDATE agendas SET finished = true, current_row = $1,
          current_row_elapsed = 0, current_row_countdown = NULL, updated_at = NOW()
         WHERE id = $2 AND user_id = $3`,
        [current_row, agendaId, req.user.id]
      );
      return res.json({ success: true, finished: true });
    }

    await pool.query(
      `UPDATE agendas SET current_row = $1,
        current_row_elapsed = 0, current_row_countdown = NULL, updated_at = NOW()
       WHERE id = $2 AND user_id = $3`,
      [nextRow, agendaId, req.user.id]
    );
    res.json({ success: true, finished: false, nextRow });
  } catch (error) {
    console.error('Proceed agenda error:', error);
    res.status(500).json({ error: 'Failed to proceed' });
  }
});

// POST /api/agendas/:agendaId/save-exit — save timer state and exit
app.post('/api/agendas/:agendaId/save-exit', authenticateToken, async (req, res) => {
  try {
    const { agendaId } = req.params;
    const { taskId, elapsedSeconds, countdownSecondsRemaining } = req.body;

    if (taskId && elapsedSeconds > 0) {
      const mins = Math.round(elapsedSeconds / 60);
      await pool.query(
        `UPDATE tasks SET accumulated_time = COALESCE(accumulated_time, 0) + $1
         WHERE id = $2 AND user_id = $3`,
        [mins, taskId, req.user.id]
      );
    }

    await pool.query(
      `UPDATE agendas SET
        current_row_elapsed = $1,
        current_row_countdown = $2,
        updated_at = NOW()
       WHERE id = $3 AND user_id = $4`,
      [elapsedSeconds || 0, countdownSecondsRemaining ?? null, agendaId, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Save-exit agenda error:', error);
    res.status(500).json({ error: 'Failed to save agenda state' });
  }
});

// DELETE /api/agendas/:agendaId
app.delete('/api/agendas/:agendaId', authenticateToken, async (req, res) => {
  try {
    const { agendaId } = req.params;
    await pool.query('DELETE FROM agendas WHERE id = $1 AND user_id = $2', [agendaId, req.user.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete agenda error:', error);
    res.status(500).json({ error: 'Failed to delete agenda' });
  }
});

// PATCH /api/agendas/:agendaId/finish
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
    const { date } = req.query; // e.g. '2026-03-17' (local date string)
    const result = await pool.query(
      `SELECT is2.period, is2.agenda_id, a.name AS agenda_name, a.rows, a.current_row, a.finished
       FROM itinerary_slots is2
       LEFT JOIN agendas a ON a.id = is2.agenda_id
       WHERE is2.user_id = $1 AND is2.date = $2`,
      [req.user.id, date]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get itinerary error:', error);
    res.status(500).json({ error: 'Failed to get itinerary' });
  }
});

// PUT /api/itinerary — assign (or clear) an agenda to a period/date slot
// Body: { date, period, agendaId } — agendaId: null to clear
app.put('/api/itinerary', authenticateToken, async (req, res) => {
  try {
    const { date, period, agendaId } = req.body;
    if (!date || !period) {
      return res.status(400).json({ error: 'date and period are required' });
    }

    if (agendaId === null || agendaId === undefined) {
      await pool.query(
        `DELETE FROM itinerary_slots WHERE user_id = $1 AND date = $2 AND period = $3`,
        [req.user.id, date, period]
      );
    } else {
      await pool.query(
        `INSERT INTO itinerary_slots (user_id, date, period, agenda_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, date, period)
         DO UPDATE SET agenda_id = $4`,
        [req.user.id, date, period, agendaId]
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

// GET /api/tutorials?date=2026-03-17 — get tutorials for a specific date
app.get('/api/tutorials', authenticateToken, async (req, res) => {
  try {
    const { date } = req.query;
    const query = date
      ? 'SELECT * FROM tutorials WHERE user_id = $1 AND date = $2 ORDER BY period ASC'
      : 'SELECT * FROM tutorials WHERE user_id = $1 ORDER BY date, period ASC';
    const params = date ? [req.user.id, date] : [req.user.id];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Get tutorials error:', error);
    res.status(500).json({ error: 'Failed to get tutorials' });
  }
});

// PUT /api/tutorials — upsert a tutorial for a date/period
app.put('/api/tutorials', authenticateToken, async (req, res) => {
  try {
    const { date, period, zoomNumber, topic } = req.body;
    if (!date || !period) {
      return res.status(400).json({ error: 'Date and period are required' });
    }
    const result = await pool.query(
      `INSERT INTO tutorials (user_id, date, period, zoom_number, topic)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, date, period)
       DO UPDATE SET zoom_number = $4, topic = $5
       RETURNING *`,
      [req.user.id, date, period, zoomNumber || null, topic || null]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Upsert tutorial error:', error);
    res.status(500).json({ error: 'Failed to save tutorial' });
  }
});

// DELETE /api/tutorials — remove a tutorial for a date/period
app.delete('/api/tutorials', authenticateToken, async (req, res) => {
  try {
    const { date, period } = req.body;
    await pool.query(
      'DELETE FROM tutorials WHERE user_id = $1 AND date = $2 AND period = $3',
      [req.user.id, date, period]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Delete tutorial error:', error);
    res.status(500).json({ error: 'Failed to delete tutorial' });
  }
});




// POST /api/tasks/normalize — no-op; priority_order removed, tasks are deadline-sorted.
app.post('/api/tasks/normalize', authenticateToken, async (req, res) => {
  res.json({ success: true });
});


// ============================================================================
// SESSION PRIORITIES — daily "today's focus" list
// ============================================================================

// GET /api/session-priorities/today — fetch today's priority list for current user
app.get('/api/session-priorities/today', authenticateToken, async (req, res) => {
  try {
    // Use client-supplied local date (avoids UTC vs local timezone mismatch for late-evening users)
    const clientDate = (req.query.date && /^\d{4}-\d{2}-\d{2}$/.test(req.query.date))
      ? req.query.date
      : null;
    const utcDate = new Date().toISOString().split('T')[0];

    // Try client local date first, then UTC date as fallback (handles records saved before fix
    // or when client/server are on different calendar days due to timezone offset)
    const datesToTry = clientDate
      ? [clientDate, ...(clientDate !== utcDate ? [utcDate] : [])]
      : [utcDate];

    let foundRow = null;
    for (const dateStr of datesToTry) {
      const result = await pool.query(
        `SELECT task_ids, date FROM session_priorities WHERE user_id = $1 AND date = $2`,
        [req.user.id, dateStr]
      );
      if (result.rows.length > 0) { foundRow = result.rows[0]; break; }
    }

    if (!foundRow) return res.json({ taskIds: null });
    res.json({ taskIds: foundRow.task_ids });
  } catch (err) {
    console.error('Get session priorities error:', err);
    res.status(500).json({ error: 'Failed to get priorities' });
  }
});

// POST /api/session-priorities/today — save today's priority list
app.post('/api/session-priorities/today', authenticateToken, async (req, res) => {
  try {
    const { taskIds, date } = req.body;
    if (!Array.isArray(taskIds)) return res.status(400).json({ error: 'taskIds must be an array' });
    // Use client-supplied local date to avoid UTC vs local timezone mismatch
    const todayStr = (date && /^\d{4}-\d{2}-\d{2}$/.test(date))
      ? date
      : new Date().toISOString().split('T')[0];
    await pool.query(
      `INSERT INTO session_priorities (user_id, date, task_ids)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, date) DO UPDATE SET task_ids = EXCLUDED.task_ids, updated_at = CURRENT_TIMESTAMP`,
      [req.user.id, todayStr, JSON.stringify(taskIds)]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Save session priorities error:', err);
    res.status(500).json({ error: 'Failed to save priorities' });
  }
});

// DELETE /api/session-priorities/today — clear today's list (start fresh)
app.delete('/api/session-priorities/today', authenticateToken, async (req, res) => {
  try {
    // Use client-supplied local date to avoid UTC vs local timezone mismatch
    const todayStr = (req.query.date && /^\d{4}-\d{2}-\d{2}$/.test(req.query.date))
      ? req.query.date
      : new Date().toISOString().split('T')[0];
    await pool.query(
      `DELETE FROM session_priorities WHERE user_id = $1 AND date = $2`,
      [req.user.id, todayStr]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear priorities' });
  }
});

// PATCH /api/tasks/:id/segment-deadline — set a per-segment deadline override
app.patch('/api/tasks/:id/segment-deadline', authenticateToken, async (req, res) => {
  try {
    const { deadlineDate, deadlineTime } = req.body;
    const taskId = req.params.id;
    if (!deadlineDate) return res.status(400).json({ error: 'deadlineDate required' });
    // Only allow on segment tasks (has a segment value)
    const check = await pool.query(
      'SELECT id, segment FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Task not found' });
    if (!check.rows[0].segment) return res.status(400).json({ error: 'Can only set individual deadlines on split segments' });
    await pool.query(
      'UPDATE tasks SET deadline_date = $1, deadline_time = $2 WHERE id = $3 AND user_id = $4',
      [deadlineDate, deadlineTime || null, taskId, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Segment deadline error:', err);
    res.status(500).json({ error: 'Failed to update segment deadline' });
  }
});


app.post('/api/tasks/manual', authenticateToken, async (req, res) => {
  try {
    const { title, deadlineDate, deadlineTime, estimatedTime, description, url, course } = req.body;
    if (!title || !deadlineDate || !deadlineTime || !estimatedTime) {
      return res.status(400).json({ error: 'title, deadlineDate, deadlineTime, and estimatedTime are required' });
    }
    // course defaults to 'Personal' which keeps existing behaviour unchanged
    const taskClass = course && course.trim() ? course.trim() : 'Personal';
    const result = await pool.query(
      `INSERT INTO tasks
         (user_id, title, segment, class, description, url, deadline_date, deadline_time,
          estimated_time, user_estimated_time, accumulated_time,
          completed, deleted, manually_created,
          course_id, assignment_id, points_possible, assignment_group_id, grading_type)
       VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8, $8, 0,
               false, false, true,
               NULL, NULL, NULL, NULL, 'not_graded')
       RETURNING *`,
      [
        req.user.id, title, taskClass, description || null, url || 'https://planassist.onrender.com/',
        deadlineDate, deadlineTime || null, estimatedTime
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

// GET /api/admin/feedback — list all feedback submissions (admin only)
app.get('/api/admin/feedback', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id, user_email, user_name, feedback_text, created_at
       FROM feedback
       ORDER BY created_at DESC
       LIMIT 200`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get admin feedback error:', err);
    res.status(500).json({ error: 'Failed to fetch feedback' });
  }
});

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
         AND (
           COALESCE(a.target_audience, 'all') = 'all'
           OR (a.target_audience = 'existing' AND $2 <= a.created_at)
           OR (a.target_audience = 'new' AND $2 > a.created_at)
         )
       ORDER BY a.created_at DESC`,
      [req.user.id, (await pool.query('SELECT created_at FROM users WHERE id = $1', [req.user.id])).rows[0]?.created_at]
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
    const audience = ['all', 'existing', 'new'].includes(req.body.target_audience) ? req.body.target_audience : 'all';
    const result = await pool.query(
      `INSERT INTO announcements (author_id, author_name, message, type, target_audience) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.user.id, adminName, message, type, audience]
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

// POST /api/admin/users/:id/grant-shield — grant one streak shield to a user
app.post('/api/admin/users/:id/grant-shield', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id;
    await pool.query(
      'UPDATE users SET streak_shields_available = streak_shields_available + 1 WHERE id = $1',
      [targetId]
    );
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const targetRes = await pool.query('SELECT name, streak_shields_available FROM users WHERE id = $1', [targetId]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'GRANT_STREAK_SHIELD', parseInt(targetId), targetRes.rows[0]?.name, {});
    res.json({ success: true, shields: targetRes.rows[0]?.streak_shields_available });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/admin/grant-shields-all — grant one shield to ALL users
app.post('/api/admin/grant-shields-all', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('UPDATE users SET streak_shields_available = streak_shields_available + 1');
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'GRANT_SHIELDS_ALL', null, null, { users_affected: r.rowCount });
    console.log(`[ADMIN] Granted shields to ${r.rowCount} users`);
    res.json({ success: true, affected: r.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================================
// ADMIN: USER MANAGEMENT
// ============================================================================

// GET /api/admin/users — list all users with stats
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.grade, u.is_admin, u.is_banned, u.ban_reason,
              u.is_new_user, u.campus, u.tz_periods, u.schedule_enhanced, u.created_at, u.last_sync,
              u.streak_shields_available,
              u.canvas_api_token IS NOT NULL AND u.canvas_api_token != '' AS has_canvas_token,
              COUNT(DISTINCT t.id) FILTER (WHERE t.deleted = false AND t.completed = false) AS active_tasks,
              MAX(tc.completed_at) AS last_completion,
              COUNT(DISTINCT tc.id) AS total_completed,
              COUNT(DISTINCT tc.id) FILTER (WHERE tc.completed_at >= NOW() - INTERVAL '7 days') AS completed_this_week,
              EXISTS(
                SELECT 1 FROM tasks st
                WHERE st.user_id = u.id
                  AND st.session_active = true
                  AND st.session_heartbeat > NOW() - INTERVAL '90 seconds'
              ) AS in_session
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
              campus, tz_periods, schedule_enhanced, created_at,
              streak_shields_available, insignia_days, insignia_selected
       FROM users WHERE id = $1`,
      [req.params.id]
    );
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    // Only fetch active (non-deleted, non-completed) tasks for the Active Tasks panel
    const tasksRes = await pool.query(
      `SELECT id, title, segment, class, deadline_date, deadline_time,
              completed, deleted, manually_created, session_active
       FROM tasks
       WHERE user_id = $1 AND deleted = false AND completed = false
       ORDER BY deadline_date ASC, deadline_time ASC NULLS LAST
       LIMIT 100`,
      [req.params.id]
    );
    const completedRes = await pool.query(
      `SELECT title, class, actual_time, estimated_time, completed_at
       FROM tasks_completed WHERE user_id = $1 ORDER BY completed_at DESC LIMIT 20`,
      [req.params.id]
    );
    res.json({ user: userRes.rows[0], tasks: tasksRes.rows, recentCompletions: completedRes.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user detail' });
  }
});

// PATCH /api/admin/users/:id — edit user fields (name, grade, campus, is_admin)
app.patch('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, grade, campus, is_admin } = req.body;
    const targetId = parseInt(req.params.id);

    // Prevent self-demotion
    if (is_admin === false && targetId === req.user.id) {
      return res.status(400).json({ error: 'You cannot remove your own admin status.' });
    }

    const fields = [];
    const vals = [];
    let idx = 1;
    if (name !== undefined)   { fields.push(`name = $${idx++}`);   vals.push(name); }
    if (grade !== undefined)  { fields.push(`grade = $${idx++}`);  vals.push(grade); }
    if (campus !== undefined) {
      const resolvedCampus = VALID_CAMPUSES.includes(campus) ? campus : 'Ashland';
      fields.push(`campus = $${idx++}`);     vals.push(resolvedCampus);
      fields.push(`tz_periods = $${idx++}`); vals.push(getEffectivePeriods(resolvedCampus));
    }
    if (is_admin !== undefined) { fields.push(`is_admin = $${idx++}`); vals.push(is_admin); }
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
    invalidateCachedToken(parseInt(targetId)); // Clear decrypt cache for this user
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const targetRes = await pool.query('SELECT name FROM users WHERE id = $1', [targetId]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'CLEAR_CANVAS_TOKEN', parseInt(targetId), targetRes.rows[0]?.name, {});
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear token' });
  }
});


// DELETE /api/admin/tasks/:taskId — admin delete a specific task
app.delete('/api/admin/tasks/:taskId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const taskRes = await pool.query('SELECT title, user_id FROM tasks WHERE id = $1', [req.params.taskId]);
    if (taskRes.rows.length === 0) return res.status(404).json({ error: 'Task not found' });
    const task = taskRes.rows[0];
    await pool.query('UPDATE tasks SET deleted = true WHERE id = $1', [req.params.taskId]);
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
    // Admin's timezone offset in minutes east of UTC (e.g. -300 for EST, +330 for IST)
    const tzOffsetMinutes = parseInt(req.query.tzOffset) || 0;
    // a) Users who haven't synced recently (no Main/Background Sync in 7 days)
    // Uses last_sync column updated by sync-save endpoint
    const staleSyncRes = await pool.query(
      `SELECT id, name, email, grade, last_sync
       FROM users
       WHERE is_new_user = false
         AND (last_sync IS NULL OR last_sync < NOW() - INTERVAL '7 days')
       ORDER BY last_sync ASC NULLS FIRST
       LIMIT 20`
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

    // Activity heatmap: completions by hour of day stored as UTC in DB.
    // We fetch all completions bucketed by UTC hour, then shift them into the
    // admin's local timezone on the JS side so bars show their local clock time.
    const heatmapRes = await pool.query(
      `SELECT EXTRACT(HOUR FROM completed_at AT TIME ZONE 'UTC')::int AS hour, COUNT(*) AS count
       FROM tasks_completed
       GROUP BY hour
       ORDER BY hour ASC`
    );
    // Build a 24-slot UTC array first
    const utcCounts = Array.from({ length: 24 }, (_, h) => {
      const found = heatmapRes.rows.find(r => parseInt(r.hour) === h);
      return found ? parseInt(found.count) : 0;
    });
    // Shift UTC hours → admin local hours using their tzOffset (minutes)
    const tzOffsetHours = tzOffsetMinutes / 60; // may be fractional for e.g. India (+5.5)
    const heatmapFull = Array.from({ length: 24 }, (_, localH) => {
      // Sum all UTC hours that map to this local hour
      let count = 0;
      for (let utcH = 0; utcH < 24; utcH++) {
        // localH = (utcH + tzOffsetHours) mod 24 — check if it rounds to localH
        const mapped = ((utcH + tzOffsetHours) % 24 + 24) % 24;
        if (Math.round(mapped) % 24 === localH) {
          count += utcCounts[utcH];
        }
      }
      return { hour: localH, count };
    });

    res.json({
      staleSyncs: staleSyncRes.rows,
      noToken: noTokenRes.rows,
      badTasks: badTasksRes.rows,
      duplicates: dupRes.rows,
      gradeStats: statsRes.rows,
      newUsers: newUsersRes.rows,
      activityHeatmap: heatmapFull
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

// GET resolved tasks (completed OR deleted, excluding split_origin)
// GET resolved tasks (completed OR deleted, excluding split_origin)
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
         AND (t.completed = TRUE OR t.deleted = TRUE)
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

    // Restore the task — deadline order is automatic, no priority needed
    await pool.query(
      `UPDATE tasks SET completed = FALSE, deleted = FALSE
       WHERE id = $1 AND user_id = $2`,
      [taskId, req.user.id]
    );

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
    const adminRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    await auditLog(req.user.id, adminRes.rows[0]?.name, 'UPDATE_HELP', null, null, {
      content_length: content?.length ?? 0
    });
    res.json({ success: true });
  } catch (error) {
    console.error('Update help content error:', error);
    res.status(500).json({ error: 'Failed to update help content' });
  }
});

// GET /api/canvas/grades — returns graded submissions from grade_history (2-month window),
// ordered by graded_at DESC. Populated by Grade Sync.
app.get('/api/canvas/grades', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, course_id, assignment_id, title, course_name, html_url,
              score, points_possible, grade, grading_type, submitted_at, graded_at, synced_at, unread
       FROM grade_history
       WHERE user_id = $1
         AND (graded_at IS NULL OR graded_at >= NOW() - INTERVAL '2 months')
       ORDER BY COALESCE(graded_at, submitted_at) DESC NULLS LAST, id DESC`,
      [req.user.id]
    );

    const graded = result.rows.map(t => ({
      id:              t.id,
      assignmentId:    t.assignment_id,
      assignmentName:  t.title,
      courseName:      t.course_name,
      score:           t.score != null ? parseFloat(t.score) : null,
      pointsPossible:  t.points_possible != null ? parseFloat(t.points_possible) : null,
      grade:           t.grade,
      gradingType:     t.grading_type || 'points',
      gradedAt:        t.graded_at || t.submitted_at,
      htmlUrl:         t.html_url,
      unread:          t.unread,
    }));

    res.json(graded);
  } catch (error) {
    console.error('Grades fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch grades' });
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

// ============================================================================
// HPT (HIGH PERFORMING TEAM) — AUTHENTICATION & MIDDLEWARE
// ============================================================================

const authenticateHPT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || !decoded.hptUser) return res.status(403).json({ error: 'Invalid HPT token' });
    req.hptUser = decoded;
    next();
  });
};

// Helper: check HPT user has access to a studio (creator or shared)
async function hptHasStudioAccess(hptUserId, studioId) {
  const r = await pool.query(
    `SELECT 1 FROM hpt_studios WHERE id=$1 AND created_by=$2
     UNION
     SELECT 1 FROM hpt_studio_shares WHERE studio_id=$1 AND hpt_user_id=$2`,
    [studioId, hptUserId]
  );
  return r.rows.length > 0;
}

// POST /api/hpt/auth/login
app.post('/api/hpt/auth/login', async (req, res) => {
  try {
    const { passcode } = req.body;
    if (!passcode) return res.status(400).json({ error: 'Passcode required' });
    const result = await pool.query('SELECT * FROM hpt_users WHERE id > 0 LIMIT 100');
    let matchedUser = null;
    for (const user of result.rows) {
      const valid = await bcrypt.compare(passcode, user.passcode_hash);
      if (valid) { matchedUser = user; break; }
    }
    if (!matchedUser) return res.status(401).json({ error: 'Invalid passcode' });
    const token = jwt.sign({ id: matchedUser.id, name: matchedUser.name, hptUser: true }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, id: matchedUser.id, name: matchedUser.name });
  } catch (err) {
    console.error('[HPT LOGIN]', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ============================================================================
// HPT STUDIOS — CRUD
// ============================================================================

// GET /api/hpt/studios — list all studios accessible to this HPT user (with live member data)
app.get('/api/hpt/studios', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;
    // Studios created by or shared with this HPT user
    const studiosRes = await pool.query(
      `SELECT DISTINCT s.*,
         (SELECT name FROM hpt_users WHERE id = s.created_by) AS creator_name
       FROM hpt_studios s
       LEFT JOIN hpt_studio_shares sh ON sh.studio_id = s.id AND sh.hpt_user_id = $1
       WHERE s.created_by = $1 OR sh.hpt_user_id = $1
       ORDER BY s.created_at ASC`,
      [hptUserId]
    );

    const studios = await Promise.all(studiosRes.rows.map(async (studio) => {
      let members = [];
      if (studio.setup_type === 'course' && studio.course_id) {
        // Derive live from courses table
        const mRes = await pool.query(
          `SELECT DISTINCT u.id, u.name, u.grade,
             c.current_score, c.current_period_score, c.current_period_grade,
             c.final_score, c.final_grade, c.course_code, c.name AS course_name,
             c.zoom_number
           FROM courses c
           JOIN users u ON u.id = c.user_id
           WHERE c.course_id = $1 AND u.is_banned = false
           ORDER BY u.name`,
          [studio.course_id]
        );
        members = mRes.rows;
      } else {
        // Key-type: explicit members — no course scores shown
        const mRes = await pool.query(
          `SELECT u.id, u.name, u.grade
           FROM hpt_studio_members sm
           JOIN users u ON u.id = sm.user_id
           WHERE sm.studio_id = $1 AND u.is_banned = false
           ORDER BY u.name`,
          [studio.id]
        );
        members = mRes.rows;
      }

      // Active banners for this studio
      const bannersRes = await pool.query(
        `SELECT id, message, author_name, created_at FROM hpt_studio_banners
         WHERE studio_id = $1 AND is_active = true ORDER BY created_at DESC`,
        [studio.id]
      );

      // Shared HPT users
      const sharesRes = await pool.query(
        `SELECT hu.id, hu.name FROM hpt_studio_shares ss
         JOIN hpt_users hu ON hu.id = ss.hpt_user_id
         WHERE ss.studio_id = $1`,
        [studio.id]
      );

      return {
        ...studio,
        members,
        banners: bannersRes.rows,
        sharedWith: sharesRes.rows,
      };
    }));

    res.json(studios);
  } catch (err) {
    console.error('[HPT STUDIOS GET]', err.message);
    res.status(500).json({ error: 'Failed to load studios' });
  }
});

// POST /api/hpt/studios/preview-course — preview members for a course_id before creating
app.post('/api/hpt/studios/preview-course', authenticateHPT, async (req, res) => {
  try {
    const { courseId } = req.body;
    if (!courseId) return res.status(400).json({ error: 'courseId required' });

    const mRes = await pool.query(
      `SELECT DISTINCT u.id, u.name, u.grade,
         c.current_score, c.current_period_score, c.current_period_grade,
         c.final_score, c.final_grade, c.course_code, c.name AS course_name,
         c.zoom_number
       FROM courses c
       JOIN users u ON u.id = c.user_id
       WHERE c.course_id = $1 AND u.is_banned = false
       ORDER BY u.name`,
      [courseId]
    );

    if (mRes.rows.length === 0) return res.status(404).json({ error: 'No students found for that course ID' });

    // Determine consensus zoom number
    const zoomNums = mRes.rows.map(r => r.zoom_number).filter(Boolean);
    const zoomFreq = {};
    zoomNums.forEach(z => { zoomFreq[z] = (zoomFreq[z] || 0) + 1; });
    const topZoom = Object.entries(zoomFreq).sort((a,b) => b[1]-a[1])[0];
    const consensusZoom = topZoom && topZoom[1] > 1 ? topZoom[0] : (zoomNums[0] || '');

    const courseName = mRes.rows[0].course_name || '';
    const courseCode = mRes.rows[0].course_code || '';

    res.json({
      courseId,
      courseName,
      courseCode,
      consensusZoom,
      members: mRes.rows,
    });
  } catch (err) {
    console.error('[HPT PREVIEW COURSE]', err.message);
    res.status(500).json({ error: 'Preview failed' });
  }
});

// POST /api/hpt/studios/generate-key — generate a unique studio key
app.post('/api/hpt/studios/generate-key', authenticateHPT, async (req, res) => {
  try {
    let key, exists = true;
    while (exists) {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      key = Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
      const r = await pool.query('SELECT 1 FROM hpt_studios WHERE studio_key = $1', [key]);
      exists = r.rows.length > 0;
    }
    res.json({ key });
  } catch (err) {
    res.status(500).json({ error: 'Key generation failed' });
  }
});

// POST /api/hpt/studios — create a new studio
app.post('/api/hpt/studios', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;
    const { setupType, courseId, studioKey, name, color, zoomNumber } = req.body;
    if (!name || !studioKey || !setupType) return res.status(400).json({ error: 'Missing required fields' });

    const result = await pool.query(
      `INSERT INTO hpt_studios (studio_key, setup_type, course_id, name, color, zoom_number, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [studioKey, setupType, courseId || null, name, color || '#7C3AED', zoomNumber || null, hptUserId]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('[HPT CREATE STUDIO]', err.message);
    res.status(500).json({ error: 'Failed to create studio' });
  }
});

// PATCH /api/hpt/studios/:id — update studio info
app.patch('/api/hpt/studios/:id', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;
    const studioId = parseInt(req.params.id);
    if (!await hptHasStudioAccess(hptUserId, studioId)) return res.status(403).json({ error: 'No access' });
    const { name, color, zoomNumber } = req.body;
    const result = await pool.query(
      `UPDATE hpt_studios SET name=$1, color=$2, zoom_number=$3, updated_at=NOW()
       WHERE id=$4 RETURNING *`,
      [name, color, zoomNumber || null, studioId]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update studio' });
  }
});

// DELETE /api/hpt/studios/:id — delete studio
app.delete('/api/hpt/studios/:id', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;
    const studioId = parseInt(req.params.id);
    if (!await hptHasStudioAccess(hptUserId, studioId)) return res.status(403).json({ error: 'No access' });
    await pool.query('DELETE FROM hpt_studios WHERE id=$1', [studioId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete studio' });
  }
});

// POST /api/hpt/studios/:id/share — share studio with another HPT user
app.post('/api/hpt/studios/:id/share', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;
    const studioId = parseInt(req.params.id);
    if (!await hptHasStudioAccess(hptUserId, studioId)) return res.status(403).json({ error: 'No access' });
    const { shareWithId } = req.body;
    if (!shareWithId) return res.status(400).json({ error: 'shareWithId required' });
    await pool.query(
      `INSERT INTO hpt_studio_shares (studio_id, hpt_user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
      [studioId, shareWithId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to share studio' });
  }
});

// DELETE /api/hpt/studios/:id/share/:hptUserId — revoke share
app.delete('/api/hpt/studios/:id/share/:hptUserId', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;
    const studioId = parseInt(req.params.id);
    if (!await hptHasStudioAccess(hptUserId, studioId)) return res.status(403).json({ error: 'No access' });
    await pool.query('DELETE FROM hpt_studio_shares WHERE studio_id=$1 AND hpt_user_id=$2', [studioId, req.params.hptUserId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke share' });
  }
});

// POST /api/hpt/studios/:id/banner — post a banner to a studio
app.post('/api/hpt/studios/:id/banner', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId, name: hptName } = req.hptUser;
    const studioId = parseInt(req.params.id);
    if (!await hptHasStudioAccess(hptUserId, studioId)) return res.status(403).json({ error: 'No access' });
    const { message } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: 'Message required' });
    // Deactivate old banners for this studio first
    await pool.query('UPDATE hpt_studio_banners SET is_active=false WHERE studio_id=$1', [studioId]);
    const result = await pool.query(
      `INSERT INTO hpt_studio_banners (studio_id, message, author_name) VALUES ($1,$2,$3) RETURNING *`,
      [studioId, message.trim(), hptName]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to post banner' });
  }
});

// DELETE /api/hpt/studios/:id/banner — deactivate studio banner
app.delete('/api/hpt/studios/:id/banner', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;
    const studioId = parseInt(req.params.id);
    if (!await hptHasStudioAccess(hptUserId, studioId)) return res.status(403).json({ error: 'No access' });
    await pool.query('UPDATE hpt_studio_banners SET is_active=false WHERE studio_id=$1', [studioId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to remove banner' });
  }
});

// GET /api/hpt/users — list all HPT users (for share picker)
app.get('/api/hpt/users', authenticateHPT, async (req, res) => {
  try {
    const { id } = req.hptUser;
    const result = await pool.query('SELECT id, name FROM hpt_users WHERE id != $1 ORDER BY name', [id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load HPT users' });
  }
});

// ============================================================================
// STUDENT: join a studio by key
// ============================================================================

// POST /api/studios/join — student joins a key-type studio
app.post('/api/studios/join', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { studioKey } = req.body;
    if (!studioKey) return res.status(400).json({ error: 'Studio key required' });

    const studioRes = await pool.query(
      'SELECT * FROM hpt_studios WHERE studio_key = $1 AND setup_type = $2',
      [studioKey.toUpperCase().trim(), 'key']
    );
    if (studioRes.rows.length === 0) return res.status(404).json({ error: 'Studio not found or this key is for a course-type studio' });
    const studio = studioRes.rows[0];

    // Insert or re-mark as unread on joining (ON CONFLICT sets unread=true so re-joins alert again)
    await pool.query(
      `INSERT INTO hpt_studio_members (studio_id, user_id, joined_at, unread)
       VALUES ($1, $2, NOW(), true)
       ON CONFLICT (studio_id, user_id) DO UPDATE SET joined_at = NOW(), unread = true`,
      [studio.id, userId]
    );
    res.json({ success: true, studioName: studio.name });
  } catch (err) {
    res.status(500).json({ error: 'Failed to join studio' });
  }
});

// GET /api/studios/mine — student: list studios they are in
app.get('/api/studios/mine', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    // Key-type studios via explicit membership
    const keyStudios = await pool.query(
      `SELECT s.id, s.name, s.color, s.setup_type, s.studio_key,
         (SELECT hu.name FROM hpt_users hu WHERE hu.id = s.created_by) AS teacher_name
       FROM hpt_studio_members sm
       JOIN hpt_studios s ON s.id = sm.studio_id
       WHERE sm.user_id = $1`,
      [userId]
    );
    // Course-type studios where user has a matching course enrollment
    const courseStudios = await pool.query(
      `SELECT DISTINCT s.id, s.name, s.color, s.setup_type, s.studio_key,
         (SELECT hu.name FROM hpt_users hu WHERE hu.id = s.created_by) AS teacher_name
       FROM hpt_studios s
       JOIN courses c ON c.course_id = s.course_id
       WHERE c.user_id = $1 AND s.setup_type = 'course'`,
      [userId]
    );

    const all = [...keyStudios.rows, ...courseStudios.rows];
    const seen = new Set();
    const unique = all.filter(s => { if (seen.has(s.id)) return false; seen.add(s.id); return true; });

    // Attach active banners and dismissal state
    const withBanners = await Promise.all(unique.map(async (studio) => {
      const bannersRes = await pool.query(
        `SELECT b.id, b.message, b.author_name, b.created_at,
           EXISTS(SELECT 1 FROM hpt_studio_banner_dismissals d WHERE d.banner_id=b.id AND d.user_id=$2) AS dismissed
         FROM hpt_studio_banners b
         WHERE b.studio_id=$1 AND b.is_active=true
         ORDER BY b.created_at DESC LIMIT 1`,
        [studio.id, userId]
      );
      return { ...studio, activeBanner: bannersRes.rows[0] || null };
    }));

    res.json(withBanners);
  } catch (err) {
    console.error('[STUDIOS MINE]', err.message);
    res.status(500).json({ error: 'Failed to load studios' });
  }
});

// POST /api/studios/banners/:bannerId/dismiss — student dismisses a banner
app.post('/api/studios/banners/:bannerId/dismiss', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO hpt_studio_banner_dismissals (user_id, banner_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [req.user.id, req.params.bannerId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to dismiss banner' });
  }
});

// ============================================================================
// ADMIN: HPT User Management
// ============================================================================

// GET /api/admin/hpt-users
app.get('/api/admin/hpt-users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT h.id, h.name, h.created_at,
         COUNT(DISTINCT s.id) AS studio_count
       FROM hpt_users h
       LEFT JOIN hpt_studios s ON s.created_by = h.id
       GROUP BY h.id ORDER BY h.name`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load HPT users' });
  }
});

// POST /api/admin/hpt-users — create HPT user
app.post('/api/admin/hpt-users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, passcode } = req.body;
    if (!name || !passcode) return res.status(400).json({ error: 'Name and passcode required' });
    const hash = await bcrypt.hash(passcode, 10);
    const result = await pool.query(
      'INSERT INTO hpt_users (name, passcode_hash) VALUES ($1,$2) RETURNING id, name, created_at',
      [name, hash]
    );
    const adminRes = await pool.query('SELECT name FROM users WHERE id=$1', [req.user.id]);
    const adminName = adminRes.rows[0]?.name || 'Admin';
    await auditLog(req.user.id, adminName, 'hpt_user_created', null, name, { name });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create HPT user' });
  }
});

// DELETE /api/admin/hpt-users/:id
app.delete('/api/admin/hpt-users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT name FROM hpt_users WHERE id=$1', [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'HPT user not found' });
    await pool.query('DELETE FROM hpt_users WHERE id=$1', [req.params.id]);
    const adminRes = await pool.query('SELECT name FROM users WHERE id=$1', [req.user.id]);
    const adminName = adminRes.rows[0]?.name || 'Admin';
    await auditLog(req.user.id, adminName, 'hpt_user_deleted', null, r.rows[0].name, {});
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete HPT user' });
  }
});

// ============================================================================
// STUDENT STUDIO BANNERS: fetch for Hub display
// ============================================================================

// GET /api/studios/hub-banners — active, undismissed banners for the current user
app.get('/api/studios/hub-banners', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      `SELECT b.id, b.message, b.author_name, s.name AS studio_name, s.color AS studio_color, b.created_at
       FROM hpt_studio_banners b
       JOIN hpt_studios s ON s.id = b.studio_id
       WHERE b.is_active = true
         AND NOT EXISTS (
           SELECT 1 FROM hpt_studio_banner_dismissals d WHERE d.banner_id=b.id AND d.user_id=$1
         )
         AND (
           (s.setup_type='course' AND EXISTS(SELECT 1 FROM courses c WHERE c.course_id=s.course_id AND c.user_id=$1))
           OR
           (s.setup_type='key' AND EXISTS(SELECT 1 FROM hpt_studio_members m WHERE m.studio_id=s.id AND m.user_id=$1))
         )
       ORDER BY b.created_at DESC`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load studio banners' });
  }
});

// ============================================================================
// HPT MONITOR — live student activity for a studio
// ============================================================================

// GET /api/hpt/studios/:id/monitor
// Returns every student in the studio with their current session state,
// today's session priorities, today's completions, and upcoming urgent tasks.
app.get('/api/hpt/studios/:id/monitor', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;
    const studioId = parseInt(req.params.id);
    if (!await hptHasStudioAccess(hptUserId, studioId)) return res.status(403).json({ error: 'No access' });

    const studioRes = await pool.query('SELECT * FROM hpt_studios WHERE id=$1', [studioId]);
    if (!studioRes.rows[0]) return res.status(404).json({ error: 'Studio not found' });
    const studio = studioRes.rows[0];

    // Get member user IDs
    let userIds = [];
    if (studio.setup_type === 'course' && studio.course_id) {
      const r = await pool.query(
        `SELECT DISTINCT c.user_id FROM courses c
         JOIN users u ON u.id=c.user_id WHERE c.course_id=$1 AND u.is_banned=false`,
        [studio.course_id]
      );
      userIds = r.rows.map(r => r.user_id);
    } else {
      const r = await pool.query(
        `SELECT sm.user_id FROM hpt_studio_members sm
         JOIN users u ON u.id=sm.user_id WHERE sm.studio_id=$1 AND u.is_banned=false`,
        [studioId]
      );
      userIds = r.rows.map(r => r.user_id);
    }
    if (userIds.length === 0) return res.json([]);

    const now = new Date();
    // Heartbeat threshold — if last heartbeat > 3 min ago, session is considered stale
    const heartbeatCutoff = new Date(now.getTime() - 3 * 60 * 1000).toISOString();
    const todayDate = now.toISOString().slice(0, 10);

    const students = await Promise.all(userIds.map(async (userId) => {
      // Basic user info
      const uRes = await pool.query(
        `SELECT id, name, grade, last_sync, streak_shields_available FROM users WHERE id=$1`,
        [userId]
      );
      const user = uRes.rows[0];
      if (!user) return null;

      // Active task (session_active=true AND heartbeat fresh)
      const activeRes = await pool.query(
        `SELECT id, title, class, estimated_time, user_estimated_time, accumulated_time,
                deadline_date, session_heartbeat
         FROM tasks
         WHERE user_id=$1 AND session_active=true AND session_heartbeat > $2
         ORDER BY session_heartbeat DESC LIMIT 1`,
        [userId, heartbeatCutoff]
      );
      const activeTask = activeRes.rows[0] || null;

      // Today's session priorities (ordered task list)
      const priRes = await pool.query(
        `SELECT sp.task_ids FROM session_priorities sp WHERE sp.user_id=$1 AND sp.date=$2`,
        [userId, todayDate]
      );
      let priorities = [];
      if (priRes.rows[0]) {
        const taskIds = priRes.rows[0].task_ids;
        if (taskIds && taskIds.length > 0) {
          const tRes = await pool.query(
            `SELECT id, title, class, estimated_time, user_estimated_time,
                    accumulated_time, deadline_date, completed
             FROM tasks WHERE id=ANY($1) AND user_id=$2`,
            [taskIds, userId]
          );
          const tMap = {};
          tRes.rows.forEach(t => { tMap[t.id] = t; });
          priorities = taskIds.map(id => tMap[id]).filter(Boolean);
        }
      }

      // Today's completions count + total time
      const compRes = await pool.query(
        `SELECT COUNT(*) AS cnt, COALESCE(SUM(actual_time),0) AS total_mins
         FROM tasks_completed WHERE user_id=$1 AND completed_at::date=$2`,
        [userId, todayDate]
      );
      const todayCompletions = {
        count: parseInt(compRes.rows[0].cnt),
        totalMins: parseInt(compRes.rows[0].total_mins),
      };

      // Upcoming urgent tasks (due today or overdue, not completed)
      const urgentRes = await pool.query(
        `SELECT id, title, class, deadline_date, estimated_time, user_estimated_time
         FROM tasks
         WHERE user_id=$1 AND completed=false AND deleted=false
           AND deadline_date <= $2
           AND LOWER(class) NOT LIKE '%homeroom%'
         ORDER BY deadline_date ASC LIMIT 5`,
        [userId, todayDate]
      );

      return {
        user: { id: user.id, name: user.name, grade: user.grade, lastSync: user.last_sync },
        isActive: !!activeTask,
        activeTask,
        priorities,
        todayCompletions,
        urgentTasks: urgentRes.rows,
      };
    }));

    res.json(students.filter(Boolean));
  } catch (err) {
    console.error('[HPT MONITOR]', err.message);
    res.status(500).json({ error: 'Failed to load monitor data' });
  }
});

// ============================================================================
// HPT HUB — aggregate stats across ALL studios the HPT user has access to
// ============================================================================

// GET /api/hpt/hub
// Returns all data needed by the HPT Hub page in a single request:
//   stats        — today/week completions, total study time, accuracy, streak (no shields)
//   feed         — recent completion_feed entries (from all connected users)
//   leaderboard  — weekly_leaderboard sorted by tasks_completed DESC (all connected users)
//   goalSnapshot — one random user's goal + course data for Goal Snapshot widget
//   inProgress   — count of tasks with accumulated_time > 0 across all connected users
app.get('/api/hpt/hub', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;

    // ── Step 1: Resolve all unique student user IDs across ALL accessible studios ──
    const studiosRes = await pool.query(
      `SELECT DISTINCT s.id, s.setup_type, s.course_id
       FROM hpt_studios s
       LEFT JOIN hpt_studio_shares sh ON sh.studio_id = s.id AND sh.hpt_user_id = $1
       WHERE s.created_by = $1 OR sh.hpt_user_id = $1`,
      [hptUserId]
    );

    const allUserIds = new Set();
    for (const studio of studiosRes.rows) {
      if (studio.setup_type === 'course' && studio.course_id) {
        const r = await pool.query(
          `SELECT DISTINCT c.user_id FROM courses c
           JOIN users u ON u.id = c.user_id
           WHERE c.course_id = $1 AND u.is_banned = false`,
          [studio.course_id]
        );
        r.rows.forEach(row => allUserIds.add(row.user_id));
      } else {
        const r = await pool.query(
          `SELECT sm.user_id FROM hpt_studio_members sm
           JOIN users u ON u.id = sm.user_id
           WHERE sm.studio_id = $1 AND u.is_banned = false`,
          [studio.id]
        );
        r.rows.forEach(row => allUserIds.add(row.user_id));
      }
    }

    const userIds = [...allUserIds].map(Number); // ensure integer array for pg ANY($1) queries
    if (userIds.length === 0) {
      return res.json({
        stats: { tasksToday: 0, tasksWeek: 0, totalStudyMins: 0, accuracy: 0, streak: 0 },
        feed: [], leaderboard: [], goalSnapshot: null, inProgress: 0, studentCount: 0,
      });
    }

    const now = new Date();
    const todayStr = now.toISOString().slice(0, 10);
    const weekStart = new Date(now);
    const dow = weekStart.getDay();
    weekStart.setDate(weekStart.getDate() - (dow === 0 ? 6 : dow - 1));
    weekStart.setHours(0, 0, 0, 0);

    // ── Step 2: Stats ─────────────────────────────────────────────────────────

    // Today completions
    const todayR = await pool.query(
      `SELECT COUNT(*) AS cnt FROM tasks_completed
       WHERE user_id = ANY($1::int[]) AND completed_at::date = $2`,
      [userIds, todayStr]
    );
    const tasksToday = parseInt(todayR.rows[0].cnt);

    // This week completions
    const weekR = await pool.query(
      `SELECT COUNT(*) AS cnt FROM tasks_completed
       WHERE user_id = ANY($1::int[]) AND completed_at >= $2`,
      [userIds, weekStart.toISOString()]
    );
    const tasksWeek = parseInt(weekR.rows[0].cnt);

    // Total study time (all time, minutes)
    const timeR = await pool.query(
      `SELECT COALESCE(SUM(actual_time), 0) AS total_mins FROM tasks_completed
       WHERE user_id = ANY($1::int[]) AND actual_time IS NOT NULL`,
      [userIds]
    );
    const totalStudyMins = parseInt(timeR.rows[0].total_mins);

    // Accuracy: avg(min(est/actual, actual/est)) across tasks with both values
    const accR = await pool.query(
      `SELECT estimated_time, actual_time FROM tasks_completed
       WHERE user_id = ANY($1::int[])
         AND estimated_time > 0 AND actual_time > 0`,
      [userIds]
    );
    let accuracy = 0;
    if (accR.rows.length > 0) {
      const sum = accR.rows.reduce((s, r) => {
        const ratio = Math.min(r.estimated_time / r.actual_time, r.actual_time / r.estimated_time);
        return s + ratio * 100;
      }, 0);
      accuracy = Math.round(sum / accR.rows.length);
    }

    // Streak: count consecutive weekdays (Mon–Fri) backwards from today/yesterday
    // where at least one completion exists for ANY connected student. No shields.
    const compDatesR = await pool.query(
      `SELECT DISTINCT completed_at::date AS day
       FROM tasks_completed
       WHERE user_id = ANY($1::int[])
       ORDER BY day ASC`,
      [userIds]
    );
    const compDateSet = new Set(compDatesR.rows.map(r => r.day.toISOString().slice(0, 10)));

    const isWeekend = (d) => { const day = new Date(d + 'T12:00:00').getDay(); return day === 0 || day === 6; };
    const prevWD = (dateStr) => {
      const d = new Date(dateStr + 'T12:00:00');
      do { d.setDate(d.getDate() - 1); } while (isWeekend(d.toISOString().slice(0, 10)));
      return d.toISOString().slice(0, 10);
    };

    let streak = 0;
    let anchor = isWeekend(todayStr) ? prevWD(todayStr) : (compDateSet.has(todayStr) ? todayStr : prevWD(todayStr));
    if (compDateSet.has(anchor)) {
      let cur = anchor;
      while (compDateSet.has(cur)) {
        streak++;
        cur = prevWD(cur);
      }
    }

    // ── Step 3: In Progress ───────────────────────────────────────────────────
    const inProgressR = await pool.query(
      `SELECT COUNT(*) AS cnt FROM tasks
       WHERE user_id = ANY($1::int[])
         AND completed = false AND deleted = false
         AND accumulated_time > 0`,
      [userIds]
    );
    const inProgress = parseInt(inProgressR.rows[0].cnt);

    // ── Step 4: Live Activity Feed ────────────────────────────────────────────
    const feedR = await pool.query(
      `SELECT cf.id, cf.user_id, cf.user_name, cf.user_grade, cf.task_title, cf.task_class,
              cf.completed_at, cf.insignia
       FROM completion_feed cf
       JOIN users u ON cf.user_id = u.id
       WHERE cf.user_id = ANY($1::int[])
         AND u.show_in_feed = true
         AND cf.completed_at > NOW() - INTERVAL '7 days'
       ORDER BY cf.completed_at DESC
       LIMIT 50`,
      [userIds]
    );

    // ── Step 5: Leaderboard (all connected users, this week, ALL grades combined) ──
    const lbR = await pool.query(
      `SELECT wl.user_id, wl.user_name, wl.grade, wl.tasks_completed,
              u.insignia_selected AS insignia
       FROM weekly_leaderboard wl
       JOIN users u ON u.id = wl.user_id
       WHERE wl.user_id = ANY($1::int[])
         AND wl.week_start = DATE_TRUNC('week', CURRENT_DATE)::date
       ORDER BY wl.tasks_completed DESC, wl.user_name ASC
       LIMIT 20`,
      [userIds]
    );

    // ── Step 6: Goal Snapshot ──────────────────────────────────────────────────
    let goalSnapshot = null;
    const goalsR = await pool.query(
      `SELECT ug.user_id, ug.course_id, ug.target_score,
              c.name AS course_name, c.current_period_score, c.grading_period_title,
              u.name AS user_name, u.grade AS user_grade
       FROM user_goals ug
       JOIN courses c ON c.user_id = ug.user_id AND c.course_id = ug.course_id
       JOIN users u ON u.id = ug.user_id
       WHERE ug.user_id = ANY($1::int[])
         AND c.current_period_score IS NOT NULL
         AND c.enabled = true
       ORDER BY RANDOM()
       LIMIT 20`,
      [userIds]
    );
    if (goalsR.rows.length > 0) {
      const idx = Math.floor(Date.now() / 1000 / 60 / 5) % goalsR.rows.length;
      goalSnapshot = goalsR.rows[idx];
    }

    res.json({
      stats: { tasksToday, tasksWeek, totalStudyMins, accuracy, streak },
      feed: feedR.rows,
      leaderboard: lbR.rows,
      goalSnapshot,
      inProgress,
      studentCount: userIds.length,
    });
  } catch (err) {
    console.error('[HPT HUB] error:', err.message, err.stack?.split('\n')[1]);
    res.status(500).json({ error: 'Failed to load hub data', details: err.message });
  }
});

// ============================================================================
// HPT MARKS — grade data for all students in a studio
// ============================================================================

// GET /api/hpt/studios/:id/marks
// Returns every student with their full course list and grade summaries.
app.get('/api/hpt/studios/:id/marks', authenticateHPT, async (req, res) => {
  try {
    const { id: hptUserId } = req.hptUser;
    const studioId = parseInt(req.params.id);
    if (!await hptHasStudioAccess(hptUserId, studioId)) return res.status(403).json({ error: 'No access' });

    const studioRes = await pool.query('SELECT * FROM hpt_studios WHERE id=$1', [studioId]);
    if (!studioRes.rows[0]) return res.status(404).json({ error: 'Studio not found' });
    const studio = studioRes.rows[0];

    let userIds = [];
    if (studio.setup_type === 'course' && studio.course_id) {
      const r = await pool.query(
        `SELECT DISTINCT c.user_id FROM courses c
         JOIN users u ON u.id=c.user_id WHERE c.course_id=$1 AND u.is_banned=false`,
        [studio.course_id]
      );
      userIds = r.rows.map(r => r.user_id);
    } else {
      const r = await pool.query(
        `SELECT sm.user_id FROM hpt_studio_members sm
         JOIN users u ON u.id=sm.user_id WHERE sm.studio_id=$1 AND u.is_banned=false`,
        [studioId]
      );
      userIds = r.rows.map(r => r.user_id);
    }
    if (userIds.length === 0) return res.json([]);

    const students = await Promise.all(userIds.map(async (userId) => {
      const uRes = await pool.query(
        `SELECT id, name, grade, last_sync FROM users WHERE id=$1`, [userId]
      );
      const user = uRes.rows[0];
      if (!user) return null;

      // Courses for this user — only those with current_period_score (active period data).
      // Excludes homeroom. current_score is returned as 'year_score' for the Year column.
      const cRes = await pool.query(
        `SELECT id, name, course_code, course_id,
                current_score          AS year_score,
                current_grade,
                current_period_score,
                current_period_grade,
                final_score,
                final_grade,
                zoom_number
         FROM courses
         WHERE user_id=$1
           AND LOWER(COALESCE(name,'')) NOT LIKE '%homeroom%'
           AND LOWER(COALESCE(course_code,'')) NOT LIKE '%homeroom%'
           AND current_period_score IS NOT NULL
         ORDER BY name`,
        [userId]
      );

      // Recent graded submissions (last 10) from grade_history
      const ghRes = await pool.query(
        `SELECT gh.title AS assignment_title, gh.course_name, gh.score, gh.points_possible,
                gh.grade, COALESCE(gh.graded_at, gh.submitted_at) AS graded_at
         FROM grade_history gh
         WHERE gh.user_id=$1
         ORDER BY COALESCE(gh.graded_at, gh.submitted_at) DESC NULLS LAST LIMIT 10`,
        [userId]
      );

      // Missing / late task count
      const missingRes = await pool.query(
        `SELECT COUNT(*) AS cnt FROM tasks
         WHERE user_id=$1 AND is_missing=true AND completed=false AND deleted=false`,
        [userId]
      );
      const lateRes = await pool.query(
        `SELECT COUNT(*) AS cnt FROM tasks
         WHERE user_id=$1 AND is_late=true AND completed=false AND deleted=false`,
        [userId]
      );

      return {
        user: { id: user.id, name: user.name, grade: user.grade, lastSync: user.last_sync },
        courses: cRes.rows,
        recentGrades: ghRes.rows,
        missingCount: parseInt(missingRes.rows[0].cnt),
        lateCount: parseInt(lateRes.rows[0].cnt),
      };
    }));

    res.json(students.filter(Boolean));
  } catch (err) {
    console.error('[HPT MARKS]', err.message);
    res.status(500).json({ error: 'Failed to load marks data' });
  }
});

// ============================================================================
// NOTIFICATIONS — sourced from grade_history, insignia_unlocks, user_badges,
// and canvas_activity (announcements, discussions, messages).
// No separate notifications table; unread flags live on the source rows.
// ============================================================================

// GET /api/notifications — unified feed sorted by event_time DESC
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      `SELECT * FROM (
         -- Unread grade notifications (must have graded_at or submitted_at — synced_at alone is not a user-facing date)
         SELECT 'grade_' || id::text AS id, 'grade' AS type, title,
                course_name AS body, html_url AS link_url, unread AS is_unread,
                COALESCE(graded_at, submitted_at) AS event_time,
                id AS source_id,
                score, points_possible, grade, grading_type,
                NULL::text AS course_name_extra
         FROM grade_history
         WHERE user_id = $1 AND unread = true
           AND COALESCE(graded_at, submitted_at) IS NOT NULL

         UNION ALL

         -- Unread insignia unlocks (must have unlocked_at)
         SELECT 'insignia_' || id::text, 'insignia',
                '🎖️ ' || label || ' Insignia Unlocked',
                'You unlocked a new Insignia tier!', NULL, unread,
                unlocked_at, id,
                NULL::numeric, NULL::numeric, NULL::varchar, NULL::varchar, NULL::text
         FROM insignia_unlocks
         WHERE user_id = $1 AND unread = true
           AND unlocked_at IS NOT NULL

         UNION ALL

         -- Unread badge awards (must have awarded_at)
         SELECT 'badge_' || id::text, 'badge',
                '🏆 ' || REPLACE(INITCAP(REPLACE(badge_key,'_',' ')),' ',' ') || ' Badge Earned',
                'You earned a new Gallery badge!', NULL, unread,
                awarded_at, id,
                NULL::numeric, NULL::numeric, NULL::varchar, NULL::varchar, NULL::text
         FROM user_badges
         WHERE user_id = $1 AND unread = true
           AND awarded_at IS NOT NULL

         UNION ALL

         -- Canvas activity (announcements, discussions, messages) — event_at is NOT NULL by schema
         SELECT 'canvas_' || id::text, type, title, body, link_url, unread,
                event_at, id,
                NULL::numeric, NULL::numeric, NULL::varchar, NULL::varchar,
                course_name AS course_name_extra
         FROM canvas_activity
         WHERE user_id = $1 AND event_at >= NOW() - INTERVAL '2 months'

         UNION ALL

         -- Unread studio joins (hpt_studio_members)
         SELECT 'studio_' || sm.id::text, 'studio',
                '📚 Joined Studio: ' || s.name,
                (SELECT hu.name FROM hpt_users hu WHERE hu.id = s.created_by), NULL, sm.unread,
                sm.joined_at, sm.id,
                NULL::numeric, NULL::numeric, NULL::varchar, NULL::varchar, NULL::text
         FROM hpt_studio_members sm
         JOIN hpt_studios s ON s.id = sm.studio_id
         WHERE sm.user_id = $1 AND sm.unread = true
           AND sm.joined_at IS NOT NULL
       ) combined
       WHERE event_time IS NOT NULL
       ORDER BY event_time DESC
       LIMIT 100`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    // If canvas_activity or new columns don't exist yet (pre-migration), return empty
    console.error('[NOTIFICATIONS] fetch error:', err.message);
    if (err.message.includes('does not exist') || err.message.includes('column') || err.message.includes('relation')) {
      return res.json([]);
    }
    res.status(500).json({ error: 'Failed to load notifications' });
  }
});

// GET /api/notifications/unread-count
app.get('/api/notifications/unread-count', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const r = await pool.query(
      `SELECT
         (SELECT COUNT(*) FROM grade_history    WHERE user_id=$1 AND unread=true) +
         (SELECT COUNT(*) FROM insignia_unlocks WHERE user_id=$1 AND unread=true) +
         (SELECT COUNT(*) FROM user_badges      WHERE user_id=$1 AND unread=true) +
         (SELECT COUNT(*) FROM canvas_activity  WHERE user_id=$1 AND unread=true) +
         (SELECT COUNT(*) FROM hpt_studio_members WHERE user_id=$1 AND unread=true) AS total`,
      [userId]
    );
    res.json({ count: parseInt(r.rows[0].total) });
  } catch (err) {
    if (err.message.includes('does not exist') || err.message.includes('column') || err.message.includes('relation')) {
      // Retry without the studio count if the column doesn't exist yet
      try {
        const r2 = await pool.query(
          `SELECT
             (SELECT COUNT(*) FROM grade_history    WHERE user_id=$1 AND unread=true) +
             (SELECT COUNT(*) FROM insignia_unlocks WHERE user_id=$1 AND unread=true) +
             (SELECT COUNT(*) FROM user_badges      WHERE user_id=$1 AND unread=true) +
             (SELECT COUNT(*) FROM canvas_activity  WHERE user_id=$1 AND unread=true) AS total`,
          [req.user.id]
        );
        return res.json({ count: parseInt(r2.rows[0].total) });
      } catch (_) { return res.json({ count: 0 }); }
    }
    res.status(500).json({ error: 'Failed to count' });
  }
});

// POST /api/notifications/read-all
app.post('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    await Promise.all([
      pool.query('UPDATE grade_history    SET unread=false WHERE user_id=$1 AND unread=true', [userId]),
      pool.query('UPDATE insignia_unlocks SET unread=false WHERE user_id=$1 AND unread=true', [userId]),
      pool.query('UPDATE user_badges      SET unread=false WHERE user_id=$1 AND unread=true', [userId]),
      pool.query('UPDATE canvas_activity  SET unread=false WHERE user_id=$1 AND unread=true', [userId]),
      pool.query('UPDATE hpt_studio_members SET unread=false WHERE user_id=$1 AND unread=true', [userId]),
    ]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to mark read' }); }
});

// PATCH /api/notifications/:id/read — id format: "grade_123", "insignia_45", "badge_67", "canvas_89"
app.patch('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const parts = req.params.id.split('_');
    const numId = parseInt(parts[parts.length - 1]);
    const type = parts[0];
    if (!numId) return res.status(400).json({ error: 'Invalid id' });
    const tableMap = { grade: 'grade_history', insignia: 'insignia_unlocks', badge: 'user_badges', canvas: 'canvas_activity', studio: 'hpt_studio_members' };
    const table = tableMap[type];
    if (!table) return res.status(400).json({ error: 'Unknown notification type' });
    await pool.query(`UPDATE ${table} SET unread=false WHERE id=$1 AND user_id=$2`, [numId, userId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to mark read' }); }
});

// GET /api/user/notification-prefs
app.get('/api/user/notification-prefs', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT notif_grades, notif_announcements, notif_discussions, notif_messages, notif_achievements, notif_studios
       FROM users WHERE id=$1`, [req.user.id]
    );
    res.json(r.rows[0] || {});
  } catch (err) { res.status(500).json({ error: 'Failed to load prefs' }); }
});

// PUT /api/user/notification-prefs
app.put('/api/user/notification-prefs', authenticateToken, async (req, res) => {
  try {
    const { notif_grades, notif_announcements, notif_discussions, notif_messages, notif_achievements, notif_studios } = req.body;
    await pool.query(
      `UPDATE users SET notif_grades=$1, notif_announcements=$2, notif_discussions=$3,
         notif_messages=$4, notif_achievements=$5, notif_studios=$6 WHERE id=$7`,
      [notif_grades ?? true, notif_announcements ?? true, notif_discussions ?? true,
       notif_messages ?? true, notif_achievements ?? true, notif_studios ?? true,
       req.user.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update prefs' }); }
});

// ============================================================================
// BACKGROUND ACTIVITY REFRESH — runs every 15 minutes, staggered across users.
// Writes into canvas_activity (announcements/discussions/messages) and
// grade_history (grades). Insignia/badge unread flags are set at insert time
// by their respective endpoints; no extra work needed here.
// ============================================================================

async function runActivityRefreshForUser(userId, canvasToken) {
  try {
    const headers = { Authorization: `Bearer ${canvasToken}` };
    const twoMonthsAgo = new Date();
    twoMonthsAgo.setMonth(twoMonthsAgo.getMonth() - 2);

    const prefsRes = await pool.query(
      `SELECT notif_grades, notif_announcements, notif_discussions, notif_messages FROM users WHERE id=$1`, [userId]
    );
    if (!prefsRes.rows[0]) return;
    const prefs = prefsRes.rows[0];

    // First-run guard: if grade_history is empty, new rows get unread=FALSE to avoid flood
    const existingCount = await pool.query('SELECT 1 FROM grade_history WHERE user_id=$1 LIMIT 1', [userId]);
    const isFirstRun = existingCount.rows.length === 0;

    // Helper: upsert canvas_activity. On URL collision, only flip unread if event_at advanced.
    const upsertActivity = async (type, title, body, courseName, linkUrl, eventAt) => {
      if (!linkUrl) return;
      await pool.query(
        `INSERT INTO canvas_activity (user_id, type, title, body, course_name, link_url, event_at, unread)
         VALUES ($1,$2,$3,$4,$5,$6,$7,true)
         ON CONFLICT (user_id, type, link_url) DO UPDATE SET
           title       = EXCLUDED.title,
           body        = EXCLUDED.body,
           course_name = EXCLUDED.course_name,
           unread      = CASE WHEN EXCLUDED.event_at > canvas_activity.event_at THEN true ELSE canvas_activity.unread END,
           event_at    = GREATEST(canvas_activity.event_at, EXCLUDED.event_at)`,
        [userId, type, title, body || null, courseName || null, linkUrl, eventAt]
      );
    };

    // --- Grades ---
    if (prefs.notif_grades) {
      try {
        const coursesRes = await pool.query(
          'SELECT DISTINCT course_id FROM courses WHERE user_id=$1 AND enabled=true AND course_id IS NOT NULL', [userId]
        );
        for (const { course_id } of coursesRes.rows) {
          const subsRes = await axios.get(
            `${CANVAS_API_BASE}/courses/${course_id}/students/submissions?student_ids[]=self&include[]=assignment&per_page=50`,
            { headers, timeout: 12000 }
          ).catch(() => ({ data: [] }));
          const courseNameRow = await pool.query('SELECT name FROM courses WHERE user_id=$1 AND course_id=$2 LIMIT 1', [userId, course_id]);
          const courseName = courseNameRow.rows[0]?.name || '';
          for (const sub of subsRes.data) {
            if (!sub.score && !sub.grade) continue;
            const gradedAt = sub.graded_at || sub.submitted_at || null;
            if (gradedAt && new Date(gradedAt) < twoMonthsAgo) continue;
            const assignment = sub.assignment || {};
            const title = assignment.name || `Assignment ${sub.assignment_id}`;
            const score = sub.score != null ? parseFloat(sub.score) : null;
            const grade = sub.grade || null;
            const pointsPoss = assignment.points_possible != null ? parseFloat(assignment.points_possible) : null;
            const htmlUrl = assignment.html_url || null;
            const gradingType = (assignment.grading_type || 'points').slice(0, 50);
            const existing = await pool.query(
              'SELECT id, score, grade FROM grade_history WHERE user_id=$1 AND assignment_id=$2',
              [userId, sub.assignment_id]
            );
            if (existing.rows.length > 0) {
              // Compare as floats to avoid false positives (DB stores "91.00", Canvas sends 91)
              const existingScore = existing.rows[0].score != null ? parseFloat(existing.rows[0].score) : null;
              const changed = existingScore !== score || existing.rows[0].grade !== grade;
              await pool.query(
                `UPDATE grade_history SET title=$1, course_name=$2, html_url=$3, score=$4, points_possible=$5,
                   grade=$6, grading_type=$7, submitted_at=$8, graded_at=$9, synced_at=NOW(),
                   unread = CASE WHEN $10 THEN true ELSE unread END
                 WHERE user_id=$11 AND assignment_id=$12`,
                [title, courseName, htmlUrl, score, pointsPoss, grade, gradingType,
                 sub.submitted_at || null, gradedAt, changed && !isFirstRun, userId, sub.assignment_id]
              );
            } else {
              await pool.query(
                `INSERT INTO grade_history
                   (user_id, course_id, assignment_id, title, course_name, html_url,
                    score, points_possible, grade, grading_type, submitted_at, graded_at, synced_at, unread)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),$13)
                 ON CONFLICT (user_id, assignment_id) DO NOTHING`,
                [userId, course_id, sub.assignment_id, title, courseName, htmlUrl,
                 score, pointsPoss, grade, gradingType, sub.submitted_at || null, gradedAt, !isFirstRun]
              );
            }
          }
        }
      } catch (e) { console.warn(`[ACTIVITY REFRESH] Grade sync failed for user ${userId}: ${e.message}`); }
    }

    // --- Announcements ---
    if (prefs.notif_announcements) {
      try {
        const annCoursesRes = await pool.query(
          'SELECT DISTINCT course_id FROM courses WHERE user_id=$1 AND enabled=true AND course_id IS NOT NULL', [userId]
        );
        const annCourseIds = annCoursesRes.rows.map(r => r.course_id);
        if (annCourseIds.length > 0) {
          const contextCodes = annCourseIds.map(cid => `context_codes[]=course_${cid}`).join('&');
          const annRes = await axios.get(
            `${CANVAS_API_BASE}/announcements?${contextCodes}&per_page=20`,
            { headers, timeout: 10000 }
          ).catch(() => ({ data: [] }));
          for (const ann of (annRes.data || [])) {
            const eventAt = ann.posted_at || ann.created_at;
            if (!eventAt || new Date(eventAt) < twoMonthsAgo) continue;
            await upsertActivity('announcement', ann.title || 'Announcement',
              ann.message ? ann.message.replace(/<[^>]+>/g, '').slice(0, 300) : null,
              ann.context_name || null, ann.html_url || null, new Date(eventAt));
          }
        }
      } catch (e) { /* silently ignore */ }
    }

    // --- Discussions ---
    if (prefs.notif_discussions) {
      try {
        const coursesRes = await pool.query(
          'SELECT DISTINCT course_id FROM courses WHERE user_id=$1 AND enabled=true AND course_id IS NOT NULL LIMIT 10', [userId]
        );
        for (const { course_id } of coursesRes.rows) {
          const discRes = await axios.get(
            `${CANVAS_API_BASE}/courses/${course_id}/discussion_topics?per_page=5&order_by=recent_activity`,
            { headers, timeout: 8000 }
          ).catch(() => ({ data: [] }));
          const cName = (await pool.query('SELECT name FROM courses WHERE user_id=$1 AND course_id=$2 LIMIT 1', [userId, course_id])).rows[0]?.name || '';
          for (const disc of (discRes.data || [])) {
            const eventAt = disc.last_reply_at || disc.posted_at || disc.created_at;
            if (!eventAt || new Date(eventAt) < twoMonthsAgo) continue;
            await upsertActivity('discussion', disc.title || 'Discussion',
              disc.message ? disc.message.replace(/<[^>]+>/g, '').slice(0, 300) : null,
              cName, disc.html_url || null, new Date(eventAt));
          }
        }
      } catch (e) { /* silently ignore */ }
    }

    // --- Messages ---
    if (prefs.notif_messages) {
      try {
        const actRes = await axios.get(
          `${CANVAS_API_BASE}/users/self/activity_stream?per_page=10`,
          { headers, timeout: 8000 }
        ).catch(() => ({ data: [] }));
        for (const item of (actRes.data || [])) {
          if (item.type !== 'Message' && item.type !== 'Conversation') continue;
          const eventAt = item.updated_at || item.created_at;
          if (!eventAt || new Date(eventAt) < twoMonthsAgo) continue;
          await upsertActivity('message', item.title || 'New message',
            item.message ? item.message.replace(/<[^>]+>/g, '').slice(0, 300) : null,
            null, item.html_url || null, new Date(eventAt));
        }
      } catch (e) { /* silently ignore */ }
    }

  } catch (err) {
    console.warn(`[ACTIVITY REFRESH] User ${userId} failed: ${err.message}`);
  }
}

// Achievement-only refresh — insignia/badge rows carry their own unread flag set
// at insert time; no separate notifications table write needed any more.
async function runAchievementNotificationsForUser(userId) {
  // No-op: unread flags on insignia_unlocks and user_badges are set by
  // /api/insignia/check-unlock and /api/badges/check at award time.
}

// Guard: prevent concurrent global refresh runs.
// With 135 users × 2-second stagger, a single run spans ~4.5 minutes.
// Without this guard, the 15-minute setInterval could overlap with a previous run
// that hasn't finished scheduling yet, causing 270 simultaneous Canvas fetches.
let _globalRefreshRunning = false;

// Background job: stagger users at 2-second intervals to avoid hammering Canvas
async function runGlobalActivityRefresh() {
  if (_globalRefreshRunning) {
    console.log('[ACTIVITY REFRESH] Previous run still in progress — skipping this interval');
    return;
  }
  _globalRefreshRunning = true;
  try {
    // Canvas-dependent refresh (grades, announcements, discussions, messages)
    const canvasUsersRes = await pool.query(
      `SELECT u.id, u.canvas_api_token, u.canvas_api_token_iv
       FROM users u
       WHERE u.is_banned = false
         AND u.canvas_api_token IS NOT NULL
         AND u.canvas_api_token != ''`
    );
    console.log(`[ACTIVITY REFRESH] Starting for ${canvasUsersRes.rows.length} Canvas users`);
    let delay = 0;
    for (const row of canvasUsersRes.rows) {
      const token = getDecryptedCanvasToken(row.id, row);
      if (!token) continue;
      setTimeout(() => runActivityRefreshForUser(row.id, token), delay);
      delay += 2000; // 2-second stagger between users
    }

    // Achievement notifications run for ALL non-banned users (no Canvas token needed)
    const allUsersRes = await pool.query(
      `SELECT id FROM users WHERE is_banned = false`
    );
    let achDelay = 500; // start slightly offset from Canvas refresh
    for (const row of allUsersRes.rows) {
      setTimeout(() => runAchievementNotificationsForUser(row.id), achDelay);
      achDelay += 200; // lighter stagger — no external API calls
    }
    // Release the guard once all setTimeout callbacks are scheduled.
    // The individual per-user refreshes run asynchronously after this point.
    const totalScheduledMs = delay;
    setTimeout(() => { _globalRefreshRunning = false; }, totalScheduledMs + 5000);

  } catch (err) {
    console.error('[ACTIVITY REFRESH] Global run failed:', err.message);
    _globalRefreshRunning = false;
  }
}

// Run every 15 minutes
setInterval(runGlobalActivityRefresh, 15 * 60 * 1000);

// GET /api/activity/data — returns all Activity pane data from the DB in one call.
// The Activity Refresh (POST /activity/refresh) is run first to populate these tables;
// this endpoint just reads them back for rendering. No live Canvas calls here.
// Tabs: grades, announcements, discussions, messages, achievements (insignia+badges), studios
app.get('/api/activity/data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const twoMonthsAgo = new Date();
    twoMonthsAgo.setMonth(twoMonthsAgo.getMonth() - 2);

    const [gradesR, announcementsR, discussionsR, messagesR, insigniaR, badgesR, studiosR] = await Promise.all([
      // Grades — from grade_history, sorted by graded_at DESC
      pool.query(
        `SELECT id, course_id, assignment_id, title, course_name, html_url,
                score, points_possible, grade, grading_type,
                submitted_at, graded_at, synced_at, unread
         FROM grade_history
         WHERE user_id = $1
           AND (graded_at IS NULL OR graded_at >= $2)
         ORDER BY COALESCE(graded_at, submitted_at) DESC NULLS LAST, id DESC
         LIMIT 100`,
        [userId, twoMonthsAgo.toISOString()]
      ),
      // Announcements — from canvas_activity
      pool.query(
        `SELECT id, title, body, course_name, link_url, event_at, unread
         FROM canvas_activity
         WHERE user_id = $1 AND type = 'announcement'
           AND event_at >= $2
         ORDER BY event_at DESC
         LIMIT 50`,
        [userId, twoMonthsAgo.toISOString()]
      ),
      // Discussions — from canvas_activity
      pool.query(
        `SELECT id, title, body, course_name, link_url, event_at, unread
         FROM canvas_activity
         WHERE user_id = $1 AND type = 'discussion'
           AND event_at >= $2
         ORDER BY event_at DESC
         LIMIT 50`,
        [userId, twoMonthsAgo.toISOString()]
      ),
      // Messages — from canvas_activity
      pool.query(
        `SELECT id, title, body, course_name, link_url, event_at, unread
         FROM canvas_activity
         WHERE user_id = $1 AND type = 'message'
           AND event_at >= $2
         ORDER BY event_at DESC
         LIMIT 50`,
        [userId, twoMonthsAgo.toISOString()]
      ),
      // Insignia unlocks
      pool.query(
        `SELECT id, label, unlocked_at, unread
         FROM insignia_unlocks
         WHERE user_id = $1
         ORDER BY unlocked_at ASC`,
        [userId]
      ),
      // Badges
      pool.query(
        `SELECT id, badge_key, awarded_at, unread
         FROM user_badges
         WHERE user_id = $1
         ORDER BY awarded_at ASC`,
        [userId]
      ),
      // Studios this user is a member of
      pool.query(
        `SELECT s.id, s.name, s.color, s.setup_type,
                (SELECT hu.name FROM hpt_users hu WHERE hu.id = s.created_by) AS teacher_name,
                sm.joined_at,
                COALESCE(sm.unread, false) AS unread
         FROM hpt_studio_members sm
         JOIN hpt_studios s ON s.id = sm.studio_id
         WHERE sm.user_id = $1
         UNION
         SELECT DISTINCT s.id, s.name, s.color, s.setup_type,
                (SELECT hu.name FROM hpt_users hu WHERE hu.id = s.created_by) AS teacher_name,
                c.updated_at AS joined_at,
                false AS unread
         FROM hpt_studios s
         JOIN courses c ON c.course_id = s.course_id AND c.user_id = $1
         WHERE s.setup_type = 'course'
         ORDER BY joined_at DESC NULLS LAST`,
        [userId]
      ),
    ]);

    res.json({
      grades:        gradesR.rows.map(g => ({
        id: g.id,
        assignmentId:   g.assignment_id,
        assignmentName: g.title,
        courseName:     g.course_name,
        score:          g.score != null ? parseFloat(g.score) : null,
        pointsPossible: g.points_possible != null ? parseFloat(g.points_possible) : null,
        grade:          g.grade,
        gradingType:    g.grading_type || 'points',
        gradedAt:       g.graded_at || g.submitted_at,
        htmlUrl:        g.html_url,
        unread:         g.unread,
      })),
      announcements: announcementsR.rows.map(a => ({
        id: a.id, title: a.title, body: a.body,
        courseName: a.course_name, htmlUrl: a.link_url,
        postedAt: a.event_at, unread: a.unread,
      })),
      discussions:   discussionsR.rows.map(d => ({
        id: d.id, title: d.title, body: d.body,
        courseName: d.course_name, htmlUrl: d.link_url,
        lastReplyAt: d.event_at, unread: d.unread,
      })),
      messages:      messagesR.rows.map(m => ({
        id: m.id, title: m.title, body: m.body,
        htmlUrl: m.link_url, updatedAt: m.event_at, unread: m.unread,
      })),
      insignia:      insigniaR.rows,
      badges:        badgesR.rows,
      studios:       studiosR.rows,
    });
  } catch (err) {
    console.error('[ACTIVITY DATA]', err.message);
    if (err.message.includes('does not exist') || err.message.includes('column') || err.message.includes('relation')) {
      return res.json({ grades: [], announcements: [], discussions: [], messages: [], insignia: [], badges: [], studios: [] });
    }
    res.status(500).json({ error: 'Failed to load activity data' });
  }
});

// POST /api/activity/refresh — triggered on login and Activity pane open.
// Runs a full refresh for the requesting user and WAITS until done before responding,
// so the frontend can await it and only show the Hub once data is ready.
app.post('/api/activity/refresh', authenticateToken, async (req, res) => {
  try {
    const userRes = await pool.query(
      'SELECT canvas_api_token, canvas_api_token_iv FROM users WHERE id=$1', [req.user.id]
    );
    const token = getDecryptedCanvasToken(req.user.id, userRes.rows[0]);
    if (token) {
      // Await the full Canvas refresh — grades, announcements, discussions, messages
      await runActivityRefreshForUser(req.user.id, token);
    } else {
      // No Canvas token — achievements only (no-op in new architecture)
      await runAchievementNotificationsForUser(req.user.id);
    }
    res.json({ done: true });
  } catch (err) {
    // Never 500 — a failed refresh should not block login
    console.warn('[ACTIVITY REFRESH]', err.message);
    res.json({ done: true, warning: err.message });
  }
});

// POST /api/courses/custom — student creates a named course entry
app.post('/api/courses/custom', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Course name required' });
    // Prevent duplicates (case-insensitive)
    const existing = await pool.query(
      'SELECT id FROM courses WHERE user_id=$1 AND LOWER(name)=LOWER($2)',
      [req.user.id, name.trim()]
    );
    if (existing.rows.length > 0) return res.status(409).json({ error: 'A course with that name already exists' });
    const result = await pool.query(
      `INSERT INTO courses (user_id, name, course_code, enabled, manually_created)
       VALUES ($1, $2, $2, true, true) RETURNING *`,
      [req.user.id, name.trim()]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Custom course create error:', err.message);
    res.status(500).json({ error: 'Failed to create course' });
  }
});

// POST /api/admin/reset-notifications — mark all unread items as read across all sources
app.post('/api/admin/reset-notifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [g, i, b, c] = await Promise.all([
      pool.query('UPDATE grade_history    SET unread=false WHERE unread=true'),
      pool.query('UPDATE insignia_unlocks SET unread=false WHERE unread=true'),
      pool.query('UPDATE user_badges      SET unread=false WHERE unread=true'),
      pool.query('UPDATE canvas_activity  SET unread=false WHERE unread=true'),
    ]);
    res.json({ updated: g.rowCount + i.rowCount + b.rowCount + c.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset notifications' });
  }
});

app.listen(PORT, () => {
  // ── Startup migrations — ADD IF NOT EXISTS for every new column and table
  // introduced since the initial schema. Safe to re-run; no data is lost.
  pool.query(`
    -- user_goals table (original migration)
    CREATE TABLE IF NOT EXISTS user_goals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      course_id BIGINT NOT NULL,
      target_score DECIMAL(5,2) NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, course_id)
    );
    CREATE INDEX IF NOT EXISTS idx_user_goals_user_id ON user_goals(user_id);

    -- tasks: new columns added in recent sessions
    ALTER TABLE tasks ADD COLUMN IF NOT EXISTS quiz_id    BIGINT;
    ALTER TABLE tasks ADD COLUMN IF NOT EXISTS inactive   BOOLEAN NOT NULL DEFAULT FALSE;

    -- grade_history: graded_at and unread
    ALTER TABLE grade_history ADD COLUMN IF NOT EXISTS graded_at TIMESTAMPTZ;
    ALTER TABLE grade_history ADD COLUMN IF NOT EXISTS unread    BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE INDEX IF NOT EXISTS idx_grade_history_graded_at ON grade_history(user_id, graded_at DESC NULLS LAST);
    CREATE INDEX IF NOT EXISTS idx_grade_history_unread    ON grade_history(user_id, unread) WHERE unread = TRUE;

    -- insignia_unlocks: unread
    ALTER TABLE insignia_unlocks ADD COLUMN IF NOT EXISTS unread BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE INDEX IF NOT EXISTS idx_insignia_unlocks_unread ON insignia_unlocks(user_id, unread) WHERE unread = TRUE;

    -- user_badges: unread
    ALTER TABLE user_badges ADD COLUMN IF NOT EXISTS unread BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE INDEX IF NOT EXISTS idx_user_badges_unread ON user_badges(user_id, unread) WHERE unread = TRUE;

    -- Widen NUMERIC columns to prevent overflow from large Canvas point values
    ALTER TABLE courses       ALTER COLUMN current_score        TYPE NUMERIC(10,2);
    ALTER TABLE courses       ALTER COLUMN final_score          TYPE NUMERIC(10,2);
    ALTER TABLE courses       ALTER COLUMN current_period_score TYPE NUMERIC(10,2);
    ALTER TABLE grade_history ALTER COLUMN score                TYPE NUMERIC(10,2);
    ALTER TABLE grade_history ALTER COLUMN points_possible      TYPE NUMERIC(10,2);

    -- hpt_studio_members: unread flag for studio join alerts
    ALTER TABLE hpt_studio_members ADD COLUMN IF NOT EXISTS unread BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE INDEX IF NOT EXISTS idx_hpt_studio_members_unread ON hpt_studio_members(user_id, unread) WHERE unread = TRUE;

    -- canvas_activity table (replaces notifications table)
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
  `).catch(err => console.error('[STARTUP MIGRATION] error:', err.message));

  console.log(`\n==============================================`);
  console.log(`  PlanAssist API v2.0 - REDESIGNED`);
  console.log(`  Server running on port ${PORT}`);
  console.log(`  Title/Segment System Active`);
  console.log(`  Advanced AI Estimation Enabled`);
  console.log(`==============================================\n`);
});
