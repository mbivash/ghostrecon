const express = require("express");
const router = express.Router();
const { scansDb } = require("../database");

// PCI-DSS Requirements mapping
const PCI_DSS_REQUIREMENTS = [
  {
    id: "PCI 2.2",
    name: "System Configuration Standards",
    description: "Develop configuration standards for all system components.",
    keywords: [
      "server version",
      "technology stack",
      "x-powered-by",
      "misconfiguration",
      "default",
    ],
    severity: "high",
  },
  {
    id: "PCI 3.4",
    name: "Protect Stored Cardholder Data",
    keywords: [
      "sensitive data",
      "credit card",
      "password in response",
      "data exposed",
      "information disclosure",
    ],
    description: "Render PAN unreadable anywhere it is stored.",
    severity: "critical",
  },
  {
    id: "PCI 4.1",
    name: "Encrypt Transmission of Cardholder Data",
    keywords: [
      "ssl",
      "tls",
      "hsts",
      "https",
      "transport",
      "cryptographic",
      "secure flag",
    ],
    description:
      "Use strong cryptography and security protocols to safeguard sensitive data during transmission.",
    severity: "critical",
  },
  {
    id: "PCI 6.2",
    name: "Protect Systems Against Known Vulnerabilities",
    keywords: [
      "cve",
      "outdated",
      "vulnerable component",
      "wordpress",
      "cms",
      "plugin",
    ],
    description:
      "Protect all system components from known vulnerabilities by installing applicable security patches.",
    severity: "high",
  },
  {
    id: "PCI 6.3",
    name: "Develop Secure Software",
    keywords: [
      "sql injection",
      "xss",
      "cross-site scripting",
      "injection",
      "csrf",
      "open redirect",
      "lfi",
      "ssrf",
    ],
    description:
      "Develop internal and external software applications securely.",
    severity: "critical",
  },
  {
    id: "PCI 6.4",
    name: "Address Common Coding Vulnerabilities",
    keywords: [
      "injection",
      "xss",
      "broken auth",
      "csrf",
      "insecure",
      "xxe",
      "idor",
    ],
    description:
      "Follow secure coding guidelines to prevent common vulnerabilities.",
    severity: "critical",
  },
  {
    id: "PCI 7.1",
    name: "Restrict Access to System Components",
    keywords: [
      "admin panel",
      "administrator",
      "access control",
      "idor",
      "broken access",
      "unauthenticated",
    ],
    description:
      "Limit access to system components to only those individuals whose job requires such access.",
    severity: "high",
  },
  {
    id: "PCI 8.2",
    name: "Identify and Authenticate Access",
    keywords: [
      "authentication",
      "jwt",
      "weak credentials",
      "default credentials",
      "rate limiting",
      "brute force",
      "broken auth",
    ],
    description:
      "Ensure proper identification and authentication of all users.",
    severity: "high",
  },
  {
    id: "PCI 10.1",
    name: "Implement Audit Trails",
    keywords: ["logging", "monitoring", "audit"],
    description:
      "Implement audit trails to link all access to system components.",
    severity: "medium",
  },
  {
    id: "PCI 11.3",
    name: "External and Internal Penetration Testing",
    keywords: ["penetration", "vulnerability", "scan"],
    description: "Perform external and internal penetration testing regularly.",
    severity: "high",
  },
  {
    id: "PCI 12.2",
    name: "Risk Assessment Process",
    keywords: ["risk", "assessment", "vulnerability management"],
    description: "Implement a risk-assessment process.",
    severity: "medium",
  },
];

// ISO 27001 Controls mapping
const ISO_27001_CONTROLS = [
  {
    id: "A.8.1",
    name: "Responsibility for Assets",
    keywords: ["sensitive data", "information disclosure", "data exposed"],
    description:
      "Identify organizational assets and define protection responsibilities.",
    severity: "medium",
  },
  {
    id: "A.9.1",
    name: "Access Control Policy",
    keywords: [
      "access control",
      "idor",
      "broken access",
      "unauthenticated",
      "admin panel",
    ],
    description: "Establish, document and review access control policy.",
    severity: "high",
  },
  {
    id: "A.9.4",
    name: "System and Application Access Control",
    keywords: [
      "authentication",
      "jwt",
      "weak credentials",
      "brute force",
      "rate limiting",
      "session",
    ],
    description: "Prevent unauthorized access to systems and applications.",
    severity: "high",
  },
  {
    id: "A.10.1",
    name: "Cryptographic Controls",
    keywords: [
      "ssl",
      "tls",
      "hsts",
      "cryptographic",
      "https",
      "certificate",
      "jwt algorithm",
      "weak algorithm",
    ],
    description: "Proper use of cryptographic controls to protect information.",
    severity: "high",
  },
  {
    id: "A.12.1",
    name: "Operational Procedures and Responsibilities",
    keywords: ["misconfiguration", "server version", "configuration"],
    description: "Establish, document and maintain operating procedures.",
    severity: "medium",
  },
  {
    id: "A.12.6",
    name: "Management of Technical Vulnerabilities",
    keywords: [
      "cve",
      "vulnerable",
      "outdated",
      "patch",
      "wordpress",
      "cms plugin",
    ],
    description:
      "Obtain information about technical vulnerabilities and take appropriate measures.",
    severity: "high",
  },
  {
    id: "A.13.1",
    name: "Network Security Management",
    keywords: ["cors", "waf", "firewall", "network", "open redirect"],
    description:
      "Manage and control networks to protect information in systems.",
    severity: "medium",
  },
  {
    id: "A.14.1",
    name: "Security Requirements of Information Systems",
    keywords: [
      "sql injection",
      "xss",
      "injection",
      "csrf",
      "ssrf",
      "xxe",
      "lfi",
    ],
    description: "Ensure security is integral part of information systems.",
    severity: "critical",
  },
  {
    id: "A.14.2",
    name: "Security in Development and Support",
    keywords: ["xss", "injection", "csrf", "insecure", "stored xss", "dom xss"],
    description:
      "Ensure security is designed and implemented within development lifecycle.",
    severity: "high",
  },
  {
    id: "A.16.1",
    name: "Management of Information Security Incidents",
    keywords: [
      "error disclosure",
      "stack trace",
      "verbose error",
      "information leakage",
    ],
    description:
      "Ensure consistent and effective approach to management of security incidents.",
    severity: "medium",
  },
  {
    id: "A.18.1",
    name: "Compliance with Legal Requirements",
    keywords: ["cookie", "gdpr", "data protection", "privacy"],
    description: "Avoid breaches of legal, statutory, regulatory obligations.",
    severity: "medium",
  },
  {
    id: "A.18.2",
    name: "Information Security Reviews",
    keywords: ["penetration", "vulnerability", "security review", "assessment"],
    description:
      "Ensure security is implemented according to organizational policies.",
    severity: "medium",
  },
];

// OWASP Top 10 2021
const OWASP_TOP_10 = [
  {
    id: "A01:2021",
    name: "Broken Access Control",
    keywords: [
      "access control",
      "idor",
      "broken access",
      "csrf",
      "open redirect",
      "cors",
    ],
  },
  {
    id: "A02:2021",
    name: "Cryptographic Failures",
    keywords: [
      "ssl",
      "tls",
      "hsts",
      "cryptographic",
      "https",
      "certificate",
      "jwt",
      "cookie secure",
      "sensitive data",
    ],
  },
  {
    id: "A03:2021",
    name: "Injection",
    keywords: [
      "sql injection",
      "xss",
      "cross-site scripting",
      "injection",
      "ssrf",
      "xxe",
      "lfi",
      "stored xss",
      "dom xss",
    ],
  },
  {
    id: "A04:2021",
    name: "Insecure Design",
    keywords: [
      "rate limiting",
      "brute force",
      "business logic",
      "mass assignment",
    ],
  },
  {
    id: "A05:2021",
    name: "Security Misconfiguration",
    keywords: [
      "misconfiguration",
      "server version",
      "x-powered-by",
      "header",
      "waf",
      "error disclosure",
      "admin panel",
      "sensitive file",
      "git",
      "env",
    ],
  },
  {
    id: "A06:2021",
    name: "Vulnerable and Outdated Components",
    keywords: [
      "cve",
      "outdated",
      "vulnerable component",
      "wordpress",
      "cms",
      "plugin",
      "version",
    ],
  },
  {
    id: "A07:2021",
    name: "Identification and Authentication Failures",
    keywords: [
      "authentication",
      "jwt",
      "weak credentials",
      "default credentials",
      "rate limiting",
      "brute force",
      "session",
      "login",
    ],
  },
  {
    id: "A08:2021",
    name: "Software and Data Integrity Failures",
    keywords: ["integrity", "supply chain", "deserialization"],
  },
  {
    id: "A09:2021",
    name: "Security Logging Failures",
    keywords: ["logging", "monitoring", "audit trail", "verbose error"],
  },
  {
    id: "A10:2021",
    name: "Server-Side Request Forgery",
    keywords: ["ssrf", "server-side request forgery"],
  },
];

function mapFindingToCompliance(finding) {
  const findingText =
    `${finding.type} ${finding.detail || ""} ${finding.owasp || ""}`.toLowerCase();

  const pciMatches = [];
  const isoMatches = [];
  const owaspMatches = [];

  PCI_DSS_REQUIREMENTS.forEach((req) => {
    if (req.keywords.some((kw) => findingText.includes(kw.toLowerCase()))) {
      pciMatches.push(req.id);
    }
  });

  ISO_27001_CONTROLS.forEach((control) => {
    if (control.keywords.some((kw) => findingText.includes(kw.toLowerCase()))) {
      isoMatches.push(control.id);
    }
  });

  OWASP_TOP_10.forEach((item) => {
    if (item.keywords.some((kw) => findingText.includes(kw.toLowerCase()))) {
      owaspMatches.push(item.id);
    }
  });

  return { pci: pciMatches, iso: isoMatches, owasp: owaspMatches };
}

function generateComplianceReport(findings, target) {
  const pciStatus = {};
  const isoStatus = {};
  const owaspStatus = {};

  PCI_DSS_REQUIREMENTS.forEach((req) => {
    pciStatus[req.id] = { ...req, violations: [], status: "pass" };
  });
  ISO_27001_CONTROLS.forEach((ctrl) => {
    isoStatus[ctrl.id] = { ...ctrl, violations: [], status: "pass" };
  });
  OWASP_TOP_10.forEach((item) => {
    owaspStatus[item.id] = { ...item, violations: [], status: "pass" };
  });

  findings.forEach((finding) => {
    const mapping = mapFindingToCompliance(finding);

    mapping.pci.forEach((id) => {
      if (pciStatus[id]) {
        pciStatus[id].violations.push({
          type: finding.type,
          severity: finding.severity,
        });
        pciStatus[id].status = "fail";
      }
    });

    mapping.iso.forEach((id) => {
      if (isoStatus[id]) {
        isoStatus[id].violations.push({
          type: finding.type,
          severity: finding.severity,
        });
        isoStatus[id].status = "fail";
      }
    });

    mapping.owasp.forEach((id) => {
      if (owaspStatus[id]) {
        owaspStatus[id].violations.push({
          type: finding.type,
          severity: finding.severity,
        });
        owaspStatus[id].status = "fail";
      }
    });
  });

  const pciResults = Object.values(pciStatus);
  const isoResults = Object.values(isoStatus);
  const owaspResults = Object.values(owaspStatus);

  const pciScore = Math.round(
    (pciResults.filter((r) => r.status === "pass").length / pciResults.length) *
      100,
  );
  const isoScore = Math.round(
    (isoResults.filter((r) => r.status === "pass").length / isoResults.length) *
      100,
  );
  const owaspScore = Math.round(
    (owaspResults.filter((r) => r.status === "pass").length /
      owaspResults.length) *
      100,
  );

  return {
    target,
    generatedAt: new Date().toISOString(),
    pci: {
      requirements: pciResults,
      score: pciScore,
      passed: pciResults.filter((r) => r.status === "pass").length,
      failed: pciResults.filter((r) => r.status === "fail").length,
      total: pciResults.length,
    },
    iso: {
      controls: isoResults,
      score: isoScore,
      passed: isoResults.filter((r) => r.status === "pass").length,
      failed: isoResults.filter((r) => r.status === "fail").length,
      total: isoResults.length,
    },
    owasp: {
      items: owaspResults,
      score: owaspScore,
      passed: owaspResults.filter((r) => r.status === "pass").length,
      failed: owaspResults.filter((r) => r.status === "fail").length,
      total: owaspResults.length,
    },
  };
}

router.post("/report", async (req, res) => {
  const { scanId } = req.body;
  if (!scanId) return res.status(400).json({ error: "Scan ID required." });

  try {
    const scan = await scansDb.findOne({ _id: scanId });
    if (!scan) return res.status(404).json({ error: "Scan not found." });

    const findings =
      scan.result?.findings || scan.result?.vulnerabilities || [];
    const report = generateComplianceReport(findings, scan.target);

    res.json({
      success: true,
      data: report,
      scan: {
        target: scan.target,
        type: scan.type,
        scannedAt: scan.scanned_at,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/scans", async (req, res) => {
  try {
    const query = req.user.role === "admin" ? {} : { userId: req.user.id };
    const scans = await scansDb.find(query).sort({ scanned_at: -1 }).limit(50);
    res.json({ success: true, scans });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
