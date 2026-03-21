const Datastore = require("nedb-promises");
const path = require("path");
const bcrypt = require("bcryptjs");

const scansDb = new Datastore({
  filename: path.join(__dirname, "scans.db"),
  autoload: true,
});

const usersDb = new Datastore({
  filename: path.join(__dirname, "users.db"),
  autoload: true,
});

async function initUsers() {
  const users = await usersDb.find({});
  if (users.length === 0) {
    const hashed = bcrypt.hashSync("ghostrecon123", 10);
    await usersDb.insert({
      name: "Admin",
      email: "ghost@recon.io",
      password: hashed,
      role: "admin",
      created_at: new Date().toISOString(),
    });
    console.log("Default user created: ghost@recon.io / ghostrecon123");
  }
}

initUsers();

module.exports = { scansDb, usersDb };
