const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL // Render sets this automatically
});
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const basicAuth = require('basic-auth');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware securitate + parsing
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Auth admin
const adminUser = "admin";
const adminPass = "password";
function auth(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.name !== adminUser || user.pass !== adminPass) {
    res.set("WWW-Authenticate", 'Basic realm="Admin Area"');
    return res.status(401).send("Authentication required.");
  }
  next();
}

// Path pentru mesaje

// GET mesaje (doar cu auth)
app.get("/api/messages", auth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM messages ORDER BY date DESC");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ status: "error", error: err.message });
  }
});

// POST mesaje (public - din formular)
app.post("/api/messages", async (req, res) => {
  const { name, email, message } = req.body;
  try {
    await pool.query(
      "INSERT INTO messages (name, email, message, date) VALUES ($1, $2, $3, NOW())",
      [name, email, message]
    );
    res.status(201).json({ status: "success" });
  } catch (err) {
    res.status(500).json({ status: "error", error: err.message });
  }
});

// Serve site-ul public
app.use(express.static(path.join(__dirname, "public")));

// Pornire server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
