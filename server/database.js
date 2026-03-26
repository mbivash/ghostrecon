const Datastore = require("nedb-promises");
const path = require("path");
const bcrypt = require("bcryptjs");
const { isTrue } = require("./config");

const scansDb = new Datastore({
  filename: path.join(__dirname, "scans.db"),
  autoload: true,
});

const usersDb = new Datastore({
  filename: path.join(__dirname, "users.db"),
  autoload: true,
});

async function initUsers() {
  const userCount = await usersDb.count({});
  if (userCount > 0) return;

  const bootstrapEnabled = isTrue(process.env.BOOTSTRAP_ADMIN);
  if (!bootstrapEnabled) {
    console.warn(
      "No users found. Set BOOTSTRAP_ADMIN=true with BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD to create initial admin.",
    );
    return;
  }

  const email = process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  const name = process.env.BOOTSTRAP_ADMIN_NAME?.trim() || "Security Admin";

  if (!email || !password) {
    throw new Error(
      "BOOTSTRAP_ADMIN=true but BOOTSTRAP_ADMIN_EMAIL/BOOTSTRAP_ADMIN_PASSWORD are missing.",
    );
  }

  const hashed = bcrypt.hashSync(password, 12);

  await usersDb.insert({
    name,
    email,
    password: hashed,
    role: "admin",
    created_at: new Date().toISOString(),
  });

  console.log(`Bootstrap admin created: ${email}`);
}

initUsers().catch((err) => {
  console.error("[DatabaseInitError]", err);
  process.exit(1);
});

module.exports = { scansDb, usersDb };
