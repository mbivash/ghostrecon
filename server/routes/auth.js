const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { usersDb } = require("../database");
const { requireEnv } = require("../config");

const router = express.Router();
const JWT_SECRET = requireEnv("JWT_SECRET");
const BCRYPT_ROUNDS = 12;

function isStrongPassword(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{10,}$/.test(password);
}

router.post("/login", async (req, res) => {
  const email = req.body?.email?.trim()?.toLowerCase();
  const password = req.body?.password;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    const user = await usersDb.findOne({ email });
    if (!user)
      return res.status(401).json({ error: "Invalid email or password." });

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid)
      return res.status(401).json({ error: "Invalid email or password." });

    const token = jwt.sign(
      { id: user._id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" },
    );

    return res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (_err) {
    return res.status(500).json({ error: "Login failed." });
  }
});

router.post("/register", async (req, res) => {
  const name = req.body?.name?.trim();
  const email = req.body?.email?.trim()?.toLowerCase();
  const password = req.body?.password;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      error:
        "Password must be at least 10 characters and include uppercase, lowercase, and a number.",
    });
  }

  try {
    const existing = await usersDb.findOne({ email });
    if (existing)
      return res.status(400).json({ error: "Email already registered." });

    const hashed = bcrypt.hashSync(password, BCRYPT_ROUNDS);

    await usersDb.insert({
      name,
      email,
      password: hashed,
      role: "analyst",
      created_at: new Date().toISOString(),
    });

    return res.json({
      success: true,
      message: "Account created. You can now log in.",
    });
  } catch (_err) {
    return res.status(500).json({ error: "Registration failed." });
  }
});

router.get("/me", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided." });
  }

  const token = authHeader.slice("Bearer ".length).trim();

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersDb.findOne({ _id: decoded.id });
    if (!user) return res.status(401).json({ error: "User not found." });

    return res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (_err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
});

module.exports = router;
