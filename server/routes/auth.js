const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../database");

const JWT_SECRET = process.env.JWT_SECRET || "ghostrecon_secret_key_2024";

// ── Login ────────────────────────────────────────────
router.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const user = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email.trim().toLowerCase());

  if (!user) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" },
  );

  res.json({
    success: true,
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
});

// ── Register ─────────────────────────────────────────
router.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }

  if (password.length < 8) {
    return res
      .status(400)
      .json({ error: "Password must be at least 8 characters." });
  }

  const existing = db
    .prepare("SELECT id FROM users WHERE email = ?")
    .get(email.toLowerCase());
  if (existing) {
    return res.status(400).json({ error: "Email already registered." });
  }

  const hashed = bcrypt.hashSync(password, 10);

  try {
    db.prepare(
      `
      INSERT INTO users (name, email, password, role)
      VALUES (?, ?, ?, ?)
    `,
    ).run(name.trim(), email.trim().toLowerCase(), hashed, "analyst");

    res.json({
      success: true,
      message: "Account created. You can now log in.",
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to create account." });
  }
});

// ── Verify token ─────────────────────────────────────
router.get("/me", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token provided." });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db
      .prepare("SELECT id, name, email, role FROM users WHERE id = ?")
      .get(decoded.id);
    if (!user) return res.status(401).json({ error: "User not found." });
    res.json({ success: true, user });
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

module.exports = router;
