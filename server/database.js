const Database = require("better-sqlite3");
const path = require("path");
const bcrypt = require("bcryptjs");

const db = new Database(path.join(__dirname, "ghostrecon.db"));

// Create scans table
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    findings_count INTEGER DEFAULT 0,
    severity TEXT DEFAULT 'info',
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Create users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'analyst',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Create default admin user if no users exist
const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get();
if (userCount.count === 0) {
  const hashed = bcrypt.hashSync("ghostrecon123", 10);
  db.prepare(
    `
    INSERT INTO users (name, email, password, role)
    VALUES (?, ?, ?, ?)
  `,
  ).run("Admin", "ghost@recon.io", hashed, "admin");
  console.log("Default user created: ghost@recon.io / ghostrecon123");
}

module.exports = db;
