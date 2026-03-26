const jwt = require("jsonwebtoken");
const { requireEnv } = require("../config");

const JWT_SECRET = requireEnv("JWT_SECRET");

module.exports = function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized. Please log in." });
  }

  const token = authHeader.slice("Bearer ".length).trim();

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (_err) {
    return res
      .status(401)
      .json({ error: "Invalid or expired token. Please log in again." });
  }
};
