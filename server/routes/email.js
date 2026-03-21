const express = require("express");
const router = express.Router();
const { sendTestEmail } = require("../utils/mailer");

router.post("/test", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required." });

  try {
    await sendTestEmail(email);
    res.json({ success: true, message: `Test email sent to ${email}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
