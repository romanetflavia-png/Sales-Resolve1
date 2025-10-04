/**
 * server.js
 * Simple Express backend:
 *  - Serves static files from ./public
 *  - POST /api/contact  -> saves message to ./data/messages.json
 *  - GET  /api/messages -> returns saved messages (protected with basic auth)
 *
 * Usage:
 *  1. put your site files in ./public (index.html, style.css, logo.jpeg, ...)
 *  2. set env vars ADMIN_USER and ADMIN_PASS (for admin route)
 *  3. node server.js
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const basicAuth = require('basic-auth');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

// Ensure data directory + messages file exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(MESSAGES_FILE)) fs.writeFileSync(MESSAGES_FILE, JSON.stringify([]));

/* --- Security middlewares --- */
app.use(helmet());
app.use(cors()); // adjust options if you want to limit origins
app.use(bodyParser.json({ limit: '10kb' })); // parse JSON request bodies

/* --- Rate limiting for form submission --- */
const contactLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 6,              // max 6 requests per IP per window
  message: { error: 'Too many submissions, please wait a bit.' }
});

/* --- Serve static files (your site) --- */
app.use(express.static(path.join(__dirname, 'public')));

/* --- Helpers --- */
function readMessages() {
  try {
    const raw = fs.readFileSync(MESSAGES_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    console.error('Error reading messages:', err);
    return [];
  }
}
function writeMessages(msgs) {
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify(msgs, null, 2));
}

/* --- Simple input sanitizer (very basic) --- */
function sanitizeString(s) {
  if (!s) return '';
  return String(s).trim().replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* --- POST /api/contact --- */
app.post('/api/contact', contactLimiter, (req, res) => {
  const { name, email, message } = req.body || {};

  // Basic validation
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Name, email and message are required.' });
  }
  if (String(message).length > 5000) {
    return res.status(400).json({ error: 'Message too long.' });
  }

  const sanitized = {
    id: Date.now(),
    name: sanitizeString(name),
    email: sanitizeString(email),
    message: sanitizeString(message),
    ip: req.ip,
    receivedAt: new Date().toISOString()
  };

  try {
    const messages = readMessages();
    messages.unshift(sanitized); // newest first
    writeMessages(messages);
    return res.json({ ok: true, message: 'Message received. Thank you!' });
  } catch (err) {
    console.error('Failed to save message:', err);
    return res.status(500).json({ error: 'Server error saving message.' });
  }
});

/* --- ADMIN: GET /api/messages (protected via Basic Auth) --- */
function requireAdmin(req, res, next) {
  const user = basicAuth(req);
  const adminUser = process.env.ADMIN_USER || 'admin';
  const adminPass = process.env.ADMIN_PASS || 'password';

  if (!user || user.name !== adminUser || user.pass !== adminPass) {
    res.set('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Authentication required.');
  }
  return next();
}

app.get('/api/messages', requireAdmin, (req, res) => {
  const messages = readMessages();
  res.json(messages);
});

/* --- Fallback: serve index.html for client-side routing (optional) --- */
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.status(404).send('Not found');
});

/* --- Start server --- */
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT}`);
});
