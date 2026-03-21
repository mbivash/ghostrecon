const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { usersDb } = require("../database");

const JWT_SECRET = process.env.JWT_SECRET || "ghostrecon_secret_key_2024";

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }
  try {
    const user = await usersDb.findOne({ email: email.trim().toLowerCase() });
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
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }
  if (password.length < 8) {
    return res
      .status(400)
      .json({ error: "Password must be at least 8 characters." });
  }
  try {
    const existing = await usersDb.findOne({ email: email.toLowerCase() });
    if (existing)
      return res.status(400).json({ error: "Email already registered." });
    const hashed = bcrypt.hashSync(password, 10);
    await usersDb.insert({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      password: hashed,
      role: "analyst",
      created_at: new Date().toISOString(),
    });
    res.json({
      success: true,
      message: "Account created. You can now log in.",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/me", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token provided." });
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersDb.findOne({ _id: decoded.id });
    if (!user) return res.status(401).json({ error: "User not found." });
    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

module.exports = router;
