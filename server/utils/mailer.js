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

  const severityColor =
    critical > 0
      ? "#E24B4A"
      : high > 0
        ? "#E24B4A"
        : medium > 0
          ? "#BA7517"
          : "#639922";
  const urgency =
    critical > 0
      ? "CRITICAL"
      : high > 0
        ? "HIGH"
        : medium > 0
          ? "MEDIUM"
          : "LOW";

  const findingsHtml = findings
    .slice(0, 5)
    .map(
      (f) => `
    <tr>
      <td style="padding:10px 14px;border-bottom:1px solid #1e1e22;">
        <span style="
          display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;
          background:${f.severity === "High" || f.severity === "Critical" ? "#1a0a0a" : f.severity === "Medium" ? "#1a1200" : "#0a1400"};
          color:${f.severity === "High" || f.severity === "Critical" ? "#E24B4A" : f.severity === "Medium" ? "#BA7517" : "#639922"};
        ">${f.severity}</span>
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
          <span style="font-size:20px;font-weight:500;color:#e8e6f0;">
            Ghost<span style="color:#7F77DD;">Recon</span>
          </span>
          <span style="margin-left:12px;font-size:12px;color:#555;">Security Alerts</span>
        </div>
        <div style="
          background:#131315;border:1px solid ${severityColor};
          border-radius:12px;padding:24px;margin-bottom:20px;">
          <div style="font-size:12px;color:${severityColor};text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">
            ${urgency} SEVERITY ALERT
          </div>
          <div style="font-size:18px;font-weight:500;color:#e8e6f0;margin-bottom:8px;">
            ${findings.length} vulnerabilities found
          </div>
          <div style="font-size:13px;color:#777;">
            Target: <span style="color:#a89ff5;font-family:monospace;">${target}</span>
          </div>
          <div style="font-size:13px;color:#777;margin-top:4px;">
            Scan type: ${scanType} · ${new Date(scanDate).toLocaleString()}
          </div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px;">
          ${[
            { label: "Critical", val: critical, color: "#ff4444" },
            { label: "High", val: high, color: "#E24B4A" },
            { label: "Medium", val: medium, color: "#BA7517" },
            { label: "Low", val: low, color: "#639922" },
          ]
            .map(
              (s) => `
            <div style="background:#131315;border:1px solid #1e1e22;border-radius:8px;padding:12px;text-align:center;">
              <div style="font-size:20px;font-weight:500;color:${s.color};">${s.val}</div>
              <div style="font-size:11px;color:#555;margin-top:2px;">${s.label}</div>
            </div>
          `,
            )
            .join("")}
        </div>
        <div style="background:#131315;border:1px solid #1e1e22;border-radius:12px;overflow:hidden;margin-bottom:20px;">
          <div style="padding:12px 14px;border-bottom:1px solid #1e1e22;font-size:11px;color:#555;text-transform:uppercase;letter-spacing:0.6px;">
            Top findings
          </div>
          <table style="width:100%;border-collapse:collapse;">
            ${findingsHtml}
          </table>
          ${
            findings.length > 5
              ? `
            <div style="padding:10px 14px;font-size:12px;color:#555;text-align:center;">
              + ${findings.length - 5} more findings
            </div>
          `
              : ""
          }
        </div>
        <div style="text-align:center;margin-bottom:24px;">
          <a href="https://ghostrecon-gold.vercel.app" style="
            display:inline-block;background:#7F77DD;color:white;
            text-decoration:none;padding:12px 32px;
            border-radius:8px;font-size:14px;font-weight:500;">
            View Full Report
          </a>
        </div>
        <div style="font-size:11px;color:#444;text-align:center;">
          GhostRecon Security Platform · Automated Security Monitoring
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
            You will now receive automatic alerts when scheduled scans find vulnerabilities.
          </div>
        </div>
      </div>
    `,
  });
}

module.exports = { sendVulnAlert, sendTestEmail };
