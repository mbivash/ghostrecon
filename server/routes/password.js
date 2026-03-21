const express = require("express");
const router = express.Router();
const crypto = require("crypto");

// ── Hash Identifier ─────────────────────────────────
router.post("/identify", (req, res) => {
  const { hash } = req.body;
  if (!hash) return res.status(400).json({ error: "Hash is required." });

  const h = hash.trim();
  const len = h.length;
  const isHex = /^[a-fA-F0-9]+$/.test(h);
  const isBase64 = /^[a-zA-Z0-9+/]+=*$/.test(h);

  const types = [];

  if (isHex) {
    if (len === 32)
      types.push({ name: "MD5", confidence: "High", crackable: true });
    if (len === 40)
      types.push({ name: "SHA-1", confidence: "High", crackable: true });
    if (len === 56)
      types.push({ name: "SHA-224", confidence: "High", crackable: false });
    if (len === 64)
      types.push({ name: "SHA-256", confidence: "High", crackable: true });
    if (len === 96)
      types.push({ name: "SHA-384", confidence: "High", crackable: false });
    if (len === 128)
      types.push({ name: "SHA-512", confidence: "High", crackable: false });
    if (len === 32)
      types.push({ name: "NTLM", confidence: "Medium", crackable: true });
    if (len === 40)
      types.push({ name: "MySQL4.1", confidence: "Low", crackable: true });
  }

  if (isBase64 && len >= 20) {
    types.push({
      name: "Base64 encoded",
      confidence: "Medium",
      crackable: false,
    });
  }

  if (h.startsWith("$2a$") || h.startsWith("$2b$") || h.startsWith("$2y$")) {
    types.push({ name: "bcrypt", confidence: "High", crackable: false });
  }

  if (h.startsWith("$1$"))
    types.push({ name: "MD5-Crypt", confidence: "High", crackable: false });
  if (h.startsWith("$5$"))
    types.push({ name: "SHA-256-Crypt", confidence: "High", crackable: false });
  if (h.startsWith("$6$"))
    types.push({ name: "SHA-512-Crypt", confidence: "High", crackable: false });

  if (types.length === 0) {
    types.push({ name: "Unknown", confidence: "Low", crackable: false });
  }

  res.json({ success: true, hash: h, types });
});

// ── Hash Cracker ─────────────────────────────────────
router.post("/crack", (req, res) => {
  const { hash, hashType } = req.body;
  if (!hash) return res.status(400).json({ error: "Hash is required." });

  const h = hash.trim().toLowerCase();

  // Common password wordlist — in production this would be rockyou.txt
  const wordlist = [
    "password",
    "123456",
    "password123",
    "admin",
    "letmein",
    "qwerty",
    "abc123",
    "monkey",
    "1234567890",
    "dragon",
    "master",
    "sunshine",
    "princess",
    "welcome",
    "shadow",
    "superman",
    "michael",
    "football",
    "iloveyou",
    "trustno1",
    "hello",
    "charlie",
    "donald",
    "password1",
    "qwerty123",
    "test",
    "root",
    "toor",
    "pass",
    "guest",
    "admin123",
    "login",
    "changeme",
    "secret",
    "default",
    "user",
    "111111",
    "000000",
    "123123",
    "654321",
    "112233",
    "passw0rd",
    "p@ssword",
    "p@ss123",
    "abc@123",
    "Admin@123",
  ];

  const algorithms =
    hashType === "sha1"
      ? ["sha1"]
      : hashType === "sha256"
        ? ["sha256"]
        : ["md5", "sha1", "sha256"];

  for (const word of wordlist) {
    for (const algo of algorithms) {
      const computed = crypto.createHash(algo).update(word).digest("hex");
      if (computed === h) {
        return res.json({
          success: true,
          cracked: true,
          password: word,
          algorithm: algo.toUpperCase(),
          attempts: wordlist.indexOf(word) + 1,
        });
      }
    }
  }

  res.json({
    success: true,
    cracked: false,
    attempts: wordlist.length * algorithms.length,
    message: "Password not found in wordlist. Try a larger wordlist.",
  });
});

// ── Password Strength Analyzer ───────────────────────
router.post("/strength", (req, res) => {
  const { password } = req.body;
  if (!password)
    return res.status(400).json({ error: "Password is required." });

  const checks = {
    length: password.length >= 12,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    numbers: /[0-9]/.test(password),
    symbols: /[^a-zA-Z0-9]/.test(password),
    noCommon: !["password", "123456", "qwerty", "admin", "letmein"].includes(
      password.toLowerCase(),
    ),
    longEnough: password.length >= 16,
  };

  const passed = Object.values(checks).filter(Boolean).length;
  const score = Math.round((passed / Object.keys(checks).length) * 100);

  let strength = "Very Weak";
  let color = "#E24B4A";
  if (score >= 85) {
    strength = "Very Strong";
    color = "#1D9E75";
  } else if (score >= 70) {
    strength = "Strong";
    color = "#639922";
  } else if (score >= 50) {
    strength = "Medium";
    color = "#BA7517";
  } else if (score >= 30) {
    strength = "Weak";
    color = "#E24B4A";
  }

  // Estimate crack time
  let charset = 0;
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/[0-9]/.test(password)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charset += 32;

  const combinations = Math.pow(charset || 1, password.length);
  const guessesPerSecond = 1e10;
  const seconds = combinations / guessesPerSecond;

  let crackTime = "instantly";
  if (seconds > 3.154e7 * 1000) crackTime = "over 1000 years";
  else if (seconds > 3.154e7 * 100) crackTime = "over 100 years";
  else if (seconds > 3.154e7 * 10) crackTime = "over 10 years";
  else if (seconds > 3.154e7) crackTime = "over 1 year";
  else if (seconds > 2.592e6) crackTime = "several months";
  else if (seconds > 86400) crackTime = "several days";
  else if (seconds > 3600) crackTime = "several hours";
  else if (seconds > 60) crackTime = "several minutes";

  res.json({
    success: true,
    score,
    strength,
    color,
    crackTime,
    length: password.length,
    checks: {
      "At least 12 characters": checks.length,
      "At least 16 characters": checks.longEnough,
      "Contains uppercase letters": checks.uppercase,
      "Contains lowercase letters": checks.lowercase,
      "Contains numbers": checks.numbers,
      "Contains symbols": checks.symbols,
      "Not a common password": checks.noCommon,
    },
  });
});

// ── Password Generator ───────────────────────────────
router.post("/generate", (req, res) => {
  const {
    length = 16,
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
  } = req.body;

  let charset = "";
  if (uppercase) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (lowercase) charset += "abcdefghijklmnopqrstuvwxyz";
  if (numbers) charset += "0123456789";
  if (symbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (!charset)
    return res
      .status(400)
      .json({ error: "Select at least one character type." });

  let password = "";
  const randomBytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    password += charset[randomBytes[i] % charset.length];
  }

  res.json({ success: true, password });
});

module.exports = router;
