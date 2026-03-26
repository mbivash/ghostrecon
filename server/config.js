function requireEnv(name) {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value.trim();
}

function getAllowedOrigins() {
  const rawOrigins =
    process.env.ALLOWED_ORIGINS || process.env.CLIENT_ORIGIN || "";
  if (!rawOrigins.trim()) return [];

  return rawOrigins
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function isTrue(value) {
  return String(value).toLowerCase() === "true";
}

module.exports = {
  requireEnv,
  getAllowedOrigins,
  isTrue,
};
