const { Resend } = require("resend");

const resend = new Resend(process.env.RESEND_API_KEY);

async function sendVulnAlert({ to, target, findings, scanType, scanDate }) {
  if (!process.env.RESEND_API_KEY) {
    console.log("Resend not configured — skipping alert");
    return;
  }

  const critical = findings.filter(
    (f) => f.severity === "Critical" || f.severity === "CRITICAL",
  ).length;
  const high = findings.filter(
    (f) => f.severity === "High" || f.severity === "HIGH",
  ).length;
  const medium = findings.filter(
    (f) => f.severity === "Medium" || f.severity === "MEDIUM",
  ).length;
  const low = findings.filter(
    (f) => f.severity === "Low" || f.severity === "LOW",
  ).length;

  const urgency =
    critical > 0
      ? "CRITICAL"
      : high > 0
        ? "HIGH"
        : medium > 0
          ? "MEDIUM"
          : "LOW";
  const severityColor =
    critical > 0
      ? "#E24B4A"
      : high > 0
        ? "#E24B4A"
        : medium > 0
          ? "#BA7517"
          : "#639922";

  const findingsHtml = findings
    .slice(0, 5)
    .map(
      (f) => `
    <tr>
      <td style="padding:10px 14px;border-bottom:1px solid #1e1e22;">
        <span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;
          background:${f.severity === "High" || f.severity === "Critical" ? "#1a0a0a" : "#1a1200"};
          color:${f.severity === "High" || f.severity === "Critical" ? "#E24B4A" : "#BA7517"};">
          ${f.severity}
        </span>
      </td>
      <td style="padding:10px 14px;border-bottom:1px solid #1e1e22;color:#ccc;font-size:13px;">
        ${f.type || f.issue || "Vulnerability found"}
      </td>
    </tr>
  `,
    )
    .join("");

  const html = `
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#0d0d0f;font-family:system-ui,sans-serif;">
      <div style="max-width:600px;margin:0 auto;padding:32px 16px;">
        <div style="margin-bottom:24px;">
          <span style="font-size:20px;font-weight:500;color:#e8e6f0;">Ghost<span style="color:#7F77DD;">Recon</span></span>
          <span style="margin-left:12px;font-size:12px;color:#555;">Security Alerts</span>
        </div>
        <div style="background:#131315;border:1px solid ${severityColor};border-radius:12px;padding:24px;margin-bottom:20px;">
          <div style="font-size:12px;color:${severityColor};text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">
            ${urgency} SEVERITY ALERT
          </div>
          <div style="font-size:18px;font-weight:500;color:#e8e6f0;margin-bottom:8px;">
            ${findings.length} vulnerabilities found
          </div>
          <div style="font-size:13px;color:#777;">
            Target: <span style="color:#a89ff5;font-family:monospace;">${target}</span>
          </div>
        </div>
        <div style="background:#131315;border:1px solid #1e1e22;border-radius:12px;overflow:hidden;margin-bottom:20px;">
          <table style="width:100%;border-collapse:collapse;">
            ${findingsHtml}
          </table>
        </div>
        <div style="text-align:center;margin-bottom:24px;">
          <a href="https://ghostrecon-gold.vercel.app" style="display:inline-block;background:#7F77DD;color:white;text-decoration:none;padding:12px 32px;border-radius:8px;font-size:14px;">
            View Full Report
          </a>
        </div>
        <div style="font-size:11px;color:#444;text-align:center;">
          GhostRecon Security Platform
        </div>
      </div>
    </body>
    </html>
  `;

  try {
    await resend.emails.send({
      from: "GhostRecon Alerts <onboarding@resend.dev>",
      to,
      subject: `[GhostRecon] ${urgency} — ${findings.length} vulnerabilities found on ${target}`,
      html,
    });
    console.log(`Alert email sent to ${to}`);
  } catch (err) {
    console.error("Email send error:", err.message);
  }
}

async function sendTestEmail(to) {
  if (!process.env.RESEND_API_KEY) {
    throw new Error(
      "Resend API key not configured. Add RESEND_API_KEY to .env",
    );
  }

  await resend.emails.send({
    from: "GhostRecon Alerts <onboarding@resend.dev>",
    to,
    subject: "GhostRecon — Email alerts configured successfully",
    html: `
      <div style="background:#0d0d0f;padding:32px;font-family:system-ui;color:#e8e6f0;">
        <div style="font-size:20px;margin-bottom:16px;">
          Ghost<span style="color:#7F77DD;">Recon</span>
        </div>
        <div style="background:#131315;border:1px solid #085041;border-radius:12px;padding:20px;">
          <div style="color:#1D9E75;font-size:14px;margin-bottom:8px;">
            Email alerts configured successfully
          </div>
          <div style="color:#777;font-size:13px;">
            You will now receive automatic alerts when vulnerabilities are found.
          </div>
        </div>
      </div>
    `,
  });
}

module.exports = { sendVulnAlert, sendTestEmail };
