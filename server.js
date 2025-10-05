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
const messagesFile = path.join(__dirname, "my-site-backend", "data", "messages.json");

// GET mesaje (doar cu auth)
app.get("/api/messages", auth, (req, res) => {
  if (!fs.existsSync(messagesFile)) {
    return res.json([]);
  }
  try {
    const data = fs.readFileSync(messagesFile, "utf8");
    const messages = JSON.parse(data || "[]");
    res.json(messages);
  } catch (e) {
    console.error("Eroare la citirea mesajelor:", e);
    res.json([]);
  }
});

// POST mesaje (public - din formular)
app.post("/api/messages", (req, res) => {
  const { name, email, message } = req.body;
  let messages = [];

  if (fs.existsSync(messagesFile)) {
    messages = JSON.parse(fs.readFileSync(messagesFile, "utf8"));
  }

  messages.push({
    name,
    email,
    message,
    date: new Date().toLocaleString()
  });

  fs.writeFileSync(messagesFile, JSON.stringify(messages, null, 2));
  res.status(201).json({ status: "success" });
});

// Serve site-ul public
app.use(express.static(path.join(__dirname, "public")));

// Pornire server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

