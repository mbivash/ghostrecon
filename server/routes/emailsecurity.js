const express = require("express");
const router = express.Router();
const dns = require("dns").promises;
const { scansDb } = require("../database");

async function checkSPF(domain) {
  const result = {
    exists: false,
    record: null,
    valid: false,
    strength: "none",
    issues: [],
    recommendations: [],
  };

  try {
    const records = await dns.resolveTxt(domain);
    const spfRecords = records
      .map((r) => r.join(""))
      .filter((r) => r.startsWith("v=spf1"));

    if (spfRecords.length === 0) {
      result.issues.push(
        "No SPF record found — anyone can send email as your domain",
      );
      result.recommendations.push(
        "Add SPF record: v=spf1 include:_spf.google.com ~all",
      );
      return result;
    }

    if (spfRecords.length > 1) {
      result.issues.push(
        "Multiple SPF records found — this breaks SPF and causes delivery issues",
      );
      result.recommendations.push(
        "Keep only one SPF record. Merge all includes into one.",
      );
    }

    result.exists = true;
    result.record = spfRecords[0];

    const spf = spfRecords[0];

    if (spf.includes("+all")) {
      result.strength = "dangerous";
      result.valid = false;
      result.issues.push(
        '"~all" or "+all" — anyone can still send as your domain',
      );
      result.recommendations.push(
        'Change to "-all" to strictly reject unauthorized senders',
      );
    } else if (spf.includes("~all")) {
      result.strength = "weak";
      result.valid = true;
      result.issues.push(
        '"~all" softfail — unauthorized emails marked as spam but not rejected',
      );
      result.recommendations.push(
        'Upgrade to "-all" for strict rejection of spoofed emails',
      );
    } else if (spf.includes("-all")) {
      result.strength = "strong";
      result.valid = true;
    } else if (spf.includes("?all")) {
      result.strength = "neutral";
      result.valid = false;
      result.issues.push('"?all" neutral — SPF provides no protection');
      result.recommendations.push('Change to "-all" for proper protection');
    }

    const includeCount = (spf.match(/include:/g) || []).length;
    if (includeCount > 10) {
      result.issues.push(
        `Too many SPF includes (${includeCount}) — exceeds DNS lookup limit of 10`,
      );
      result.recommendations.push(
        "Flatten SPF record using a service like dmarcanalyzer.com",
      );
    }
  } catch (e) {
    if (e.code === "ENODATA" || e.code === "ENOTFOUND") {
      result.issues.push(
        "No SPF record found — domain is vulnerable to email spoofing",
      );
      result.recommendations.push(
        "Add SPF record immediately: v=spf1 include:_spf.google.com -all",
      );
    }
  }

  return result;
}

async function checkDKIM(domain) {
  const result = {
    exists: false,
    selectors: [],
    issues: [],
    recommendations: [],
  };

  const commonSelectors = [
    "default",
    "google",
    "mail",
    "email",
    "dkim",
    "smtp",
    "k1",
    "k2",
    "s1",
    "s2",
    "selector1",
    "selector2",
    "zoho",
    "mailchimp",
    "sendgrid",
    "mandrill",
    "amazonses",
  ];

  for (const selector of commonSelectors) {
    try {
      const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      const dkimRecord = records
        .map((r) => r.join(""))
        .find((r) => r.includes("v=DKIM1") || r.includes("p="));
      if (dkimRecord) {
        result.exists = true;
        result.selectors.push({
          selector,
          record: dkimRecord.substring(0, 100) + "...",
          valid:
            dkimRecord.includes("p=") &&
            !dkimRecord.includes("p=;") &&
            !dkimRecord.includes("p= "),
        });
      }
    } catch (e) {}
  }

  if (!result.exists) {
    result.issues.push(
      "No DKIM records found — emails cannot be cryptographically verified",
    );
    result.recommendations.push(
      "Enable DKIM signing in your email provider (Gmail, Outlook, etc.)",
    );
    result.recommendations.push(
      "Add the DKIM TXT record provided by your email provider to your DNS",
    );
  }

  return result;
}

async function checkDMARC(domain) {
  const result = {
    exists: false,
    record: null,
    policy: "none",
    policyStrength: "none",
    percentage: 100,
    reportingEnabled: false,
    issues: [],
    recommendations: [],
  };

  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    const dmarcRecord = records
      .map((r) => r.join(""))
      .find((r) => r.startsWith("v=DMARC1"));

    if (!dmarcRecord) {
      result.issues.push(
        "No DMARC record found — no policy for handling spoofed emails",
      );
      result.recommendations.push(
        "Add DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain,
      );
      return result;
    }

    result.exists = true;
    result.record = dmarcRecord;

    const policyMatch = dmarcRecord.match(/p=(\w+)/);
    if (policyMatch) {
      result.policy = policyMatch[1].toLowerCase();
      result.policyStrength = result.policy;

      if (result.policy === "none") {
        result.issues.push(
          'DMARC policy is "none" — emails are monitored but not rejected',
        );
        result.recommendations.push(
          "Upgrade to p=quarantine then p=reject once you have reviewed reports",
        );
      } else if (result.policy === "quarantine") {
        result.issues.push(
          'DMARC policy is "quarantine" — spoofed emails go to spam but not rejected',
        );
        result.recommendations.push(
          "Upgrade to p=reject for full protection once confident in configuration",
        );
      } else if (result.policy === "reject") {
        // Good
      }
    }

    const pctMatch = dmarcRecord.match(/pct=(\d+)/);
    if (pctMatch) {
      result.percentage = parseInt(pctMatch[1]);
      if (result.percentage < 100) {
        result.issues.push(
          `DMARC only applies to ${result.percentage}% of emails — not fully enforced`,
        );
        result.recommendations.push(
          "Increase pct=100 to apply policy to all emails",
        );
      }
    }

    if (dmarcRecord.includes("rua=") || dmarcRecord.includes("ruf=")) {
      result.reportingEnabled = true;
    } else {
      result.issues.push(
        "No DMARC reporting configured — you cannot see who is spoofing your domain",
      );
      result.recommendations.push(
        "Add rua=mailto:dmarc-reports@" +
          domain +
          " to receive aggregate reports",
      );
    }
  } catch (e) {
    result.issues.push(
      "No DMARC record found — no policy for handling spoofed emails",
    );
    result.recommendations.push(
      "Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain,
    );
  }

  return result;
}

async function checkMX(domain) {
  const result = {
    exists: false,
    records: [],
    provider: "Unknown",
    issues: [],
    recommendations: [],
  };

  try {
    const records = await dns.resolveMx(domain);
    result.exists = records.length > 0;
    result.records = records.sort((a, b) => a.priority - b.priority);

    const mxString = records
      .map((r) => r.exchange)
      .join(" ")
      .toLowerCase();

    if (mxString.includes("google") || mxString.includes("googlemail"))
      result.provider = "Google Workspace";
    else if (mxString.includes("outlook") || mxString.includes("microsoft"))
      result.provider = "Microsoft 365";
    else if (mxString.includes("zoho")) result.provider = "Zoho Mail";
    else if (mxString.includes("amazonses")) result.provider = "Amazon SES";
    else if (mxString.includes("mailgun")) result.provider = "Mailgun";
    else if (mxString.includes("sendgrid")) result.provider = "SendGrid";
    else if (mxString.includes("protonmail")) result.provider = "ProtonMail";
    else result.provider = records[0]?.exchange || "Custom mail server";

    if (records.length === 1) {
      result.issues.push(
        "Only one MX record — no email redundancy. If this server goes down, you lose all email",
      );
      result.recommendations.push(
        "Add a secondary MX record for email redundancy",
      );
    }
  } catch (e) {
    result.issues.push("No MX records found — domain cannot receive email");
    result.recommendations.push(
      "Add MX records to enable email for this domain",
    );
  }

  return result;
}

async function checkEmailSpoofing(domain) {
  const result = {
    spoofable: false,
    reason: "",
    severity: "Low",
  };

  try {
    const txtRecords = await dns.resolveTxt(domain);
    const spf = txtRecords
      .map((r) => r.join(""))
      .find((r) => r.startsWith("v=spf1"));

    let dmarcRecord = null;
    try {
      const dmarcTxt = await dns.resolveTxt(`_dmarc.${domain}`);
      dmarcRecord = dmarcTxt
        .map((r) => r.join(""))
        .find((r) => r.startsWith("v=DMARC1"));
    } catch (e) {}

    const spfStrong = spf && spf.includes("-all");
    const dmarcStrong =
      dmarcRecord &&
      (dmarcRecord.includes("p=reject") ||
        dmarcRecord.includes("p=quarantine"));

    if (!spf && !dmarcRecord) {
      result.spoofable = true;
      result.severity = "Critical";
      result.reason =
        "No SPF or DMARC — anyone can send email as @" + domain + " right now";
    } else if (!spf) {
      result.spoofable = true;
      result.severity = "High";
      result.reason = "No SPF record — email spoofing possible despite DMARC";
    } else if (!dmarcRecord) {
      result.spoofable = true;
      result.severity = "High";
      result.reason = "No DMARC — SPF alone is not enough to prevent spoofing";
    } else if (!spfStrong && !dmarcStrong) {
      result.spoofable = true;
      result.severity = "Medium";
      result.reason = "Weak SPF and DMARC — spoofed emails may reach inbox";
    } else if (!dmarcStrong) {
      result.spoofable = true;
      result.severity = "Medium";
      result.reason =
        "DMARC policy is not enforced (p=none) — spoofed emails not blocked";
    } else {
      result.spoofable = false;
      result.reason = "Domain is well protected against email spoofing";
    }
  } catch (e) {
    result.spoofable = true;
    result.severity = "Critical";
    result.reason =
      "Could not verify email security — domain may be unprotected";
  }

  return result;
}

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target) return res.status(400).json({ error: "Domain is required." });

  let domain = target
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .trim();

  console.log("Email security scan for:", domain);

  try {
    const [spf, dkim, dmarc, mx, spoofing] = await Promise.all([
      checkSPF(domain),
      checkDKIM(domain),
      checkDMARC(domain),
      checkMX(domain),
      checkEmailSpoofing(domain),
    ]);

    const allIssues = [
      ...spf.issues.map((i) => ({
        source: "SPF",
        issue: i,
        severity: spf.strength === "none" ? "Critical" : "High",
      })),
      ...dkim.issues.map((i) => ({
        source: "DKIM",
        issue: i,
        severity: "High",
      })),
      ...dmarc.issues.map((i) => ({
        source: "DMARC",
        issue: i,
        severity: dmarc.policy === "none" ? "High" : "Medium",
      })),
      ...mx.issues.map((i) => ({ source: "MX", issue: i, severity: "Low" })),
    ];

    const score = Math.max(
      0,
      100 -
        (spf.exists ? 0 : 30) -
        (spf.strength === "strong" ? 0 : spf.strength === "weak" ? 10 : 20) -
        (dkim.exists ? 0 : 25) -
        (dmarc.exists ? 0 : 25) -
        (dmarc.policy === "reject"
          ? 0
          : dmarc.policy === "quarantine"
            ? 5
            : 15) -
        (mx.exists ? 0 : 10) -
        (mx.records.length > 1 ? 0 : 5),
    );

    const result = {
      domain,
      score,
      spoofable: spoofing.spoofable,
      spoofReason: spoofing.reason,
      spoofSeverity: spoofing.severity,
      spf,
      dkim,
      dmarc,
      mx,
      allIssues,
      scannedAt: new Date().toISOString(),
    };

    const severity = spoofing.severity.toLowerCase();
    scansDb
      .insert({
        type: "Email Security Scan",
        userId: req.user?.id,
        target: domain,
        result,
        findings_count: allIssues.length,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: result });
  } catch (err) {
    console.error("Email security error:", err);
    res.status(500).json({ error: "Scan failed: " + err.message });
  }
});

module.exports = router;
