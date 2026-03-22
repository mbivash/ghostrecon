const express = require("express");
const router = express.Router();
const PDFDocument = require("pdfkit");
const { scansDb } = require("../database");

const COLORS = {
  bg: "#0d0d0f",
  surface: "#131315",
  border: "#1e1e22",
  purple: "#7F77DD",
  purpleLight: "#a89ff5",
  critical: "#ff4444",
  high: "#E24B4A",
  medium: "#BA7517",
  low: "#639922",
  info: "#7F77DD",
  text: "#e8e6f0",
  textMuted: "#777777",
  textDim: "#555555",
  green: "#1D9E75",
  white: "#ffffff",
};

function hexToRgb(hex) {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result
    ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16),
      }
    : { r: 0, g: 0, b: 0 };
}

function setColor(doc, hex) {
  const { r, g, b } = hexToRgb(hex);
  doc.fillColor([r, g, b]);
}

function setStroke(doc, hex) {
  const { r, g, b } = hexToRgb(hex);
  doc.strokeColor([r, g, b]);
}

function getSeverityColor(severity) {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return COLORS.critical;
  if (s === "high") return COLORS.high;
  if (s === "medium") return COLORS.medium;
  if (s === "low") return COLORS.low;
  return COLORS.info;
}

function drawBackground(doc) {
  const { r, g, b } = hexToRgb(COLORS.bg);
  doc.rect(0, 0, doc.page.width, doc.page.height).fill([r, g, b]);
}

function drawCoverPage(doc, scan, summary) {
  drawBackground(doc);

  // Top accent bar
  const { r: pr, g: pg, b: pb } = hexToRgb(COLORS.purple);
  doc.rect(0, 0, doc.page.width, 4).fill([pr, pg, pb]);

  // Logo area
  setColor(doc, COLORS.purple);
  doc.fontSize(32).font("Helvetica-Bold");
  doc.text("Ghost", 60, 80, { continued: true });
  setColor(doc, COLORS.purpleLight);
  doc.text("Recon", { continued: false });

  setColor(doc, COLORS.textDim);
  doc.fontSize(11).font("Helvetica");
  doc.text("Professional Security Assessment Platform", 60, 120);

  // Divider
  setStroke(doc, COLORS.border);
  doc
    .moveTo(60, 145)
    .lineTo(doc.page.width - 60, 145)
    .lineWidth(0.5)
    .stroke();

  // Report title
  setColor(doc, COLORS.text);
  doc.fontSize(28).font("Helvetica-Bold");
  doc.text("Web Application", 60, 180);
  doc.text("Security Report", 60, 215);

  setColor(doc, COLORS.textMuted);
  doc.fontSize(13).font("Helvetica");
  doc.text("Automated Security Assessment", 60, 255);

  // Target info box
  const boxY = 310;
  const { r: sr, g: sg, b: sb } = hexToRgb(COLORS.surface);
  doc.rect(60, boxY, doc.page.width - 120, 140).fill([sr, sg, sb]);
  setStroke(doc, COLORS.border);
  doc
    .rect(60, boxY, doc.page.width - 120, 140)
    .lineWidth(0.5)
    .stroke();

  // Purple left accent on box
  doc.rect(60, boxY, 3, 140).fill([pr, pg, pb]);

  setColor(doc, COLORS.textDim);
  doc.fontSize(9).font("Helvetica");
  doc.text("TARGET", 80, boxY + 20);

  setColor(doc, COLORS.text);
  doc.fontSize(16).font("Helvetica-Bold");
  doc.text(scan.target || "Unknown", 80, boxY + 35, {
    width: doc.page.width - 160,
  });

  setColor(doc, COLORS.textDim);
  doc.fontSize(9).font("Helvetica");
  doc.text("SCAN DATE", 80, boxY + 70);
  doc.text("SCAN TYPE", 250, boxY + 70);
  doc.text("REPORT ID", 420, boxY + 70);

  setColor(doc, COLORS.textMuted);
  doc.fontSize(11).font("Helvetica");
  doc.text(
    new Date(scan.scanned_at).toLocaleDateString("en-GB", {
      day: "2-digit",
      month: "long",
      year: "numeric",
    }),
    80,
    boxY + 85,
  );
  doc.text(scan.type || "Web Vulnerability Scan", 250, boxY + 85);
  doc.text(
    scan._id ? scan._id.substring(0, 8).toUpperCase() : "GR000001",
    420,
    boxY + 85,
  );

  // Risk score section
  const scoreY = 490;
  const riskScore = scan.result?.riskScore || 0;
  const scoreColor =
    riskScore >= 70
      ? COLORS.critical
      : riskScore >= 40
        ? COLORS.medium
        : COLORS.green;

  setColor(doc, COLORS.textDim);
  doc.fontSize(9).font("Helvetica");
  doc.text("OVERALL RISK SCORE", 60, scoreY);

  // Score gauge background
  const gaugeX = 60;
  const gaugeY = scoreY + 15;
  const gaugeW = doc.page.width - 120;
  const gaugeH = 12;
  const { r: br2, g: bg2, b: bb2 } = hexToRgb("#1e1e22");
  doc.rect(gaugeX, gaugeY, gaugeW, gaugeH).fill([br2, bg2, bb2]);

  // Score fill
  const fillW = (riskScore / 100) * gaugeW;
  const { r: scr, g: scg, b: scb } = hexToRgb(scoreColor);
  doc.rect(gaugeX, gaugeY, fillW, gaugeH).fill([scr, scg, scb]);

  // Score number
  setColor(doc, scoreColor);
  doc.fontSize(48).font("Helvetica-Bold");
  doc.text(`${riskScore}`, 60, scoreY + 35);

  setColor(doc, COLORS.textDim);
  doc.fontSize(11).font("Helvetica");
  doc.text(
    "/100",
    60 + (riskScore >= 100 ? 88 : riskScore >= 10 ? 72 : 40),
    scoreY + 55,
  );

  const riskLabel =
    riskScore >= 70
      ? "CRITICAL RISK"
      : riskScore >= 40
        ? "MEDIUM RISK"
        : riskScore >= 10
          ? "LOW RISK"
          : "MINIMAL RISK";
  setColor(doc, scoreColor);
  doc.fontSize(14).font("Helvetica-Bold");
  doc.text(riskLabel, 60, scoreY + 85);

  // Summary stats row
  const statsY = scoreY + 120;
  const statItems = [
    { label: "Critical", val: summary.critical, color: COLORS.critical },
    { label: "High", val: summary.high, color: COLORS.high },
    { label: "Medium", val: summary.medium, color: COLORS.medium },
    { label: "Low", val: summary.low, color: COLORS.low },
    { label: "Total", val: summary.total, color: COLORS.purple },
  ];

  const statW = (doc.page.width - 120) / statItems.length;
  statItems.forEach((stat, i) => {
    const sx = 60 + i * statW;
    const { r: str, g: stg, b: stb } = hexToRgb(COLORS.surface);
    doc.rect(sx, statsY, statW - 8, 60).fill([str, stg, stb]);
    setStroke(doc, COLORS.border);
    doc
      .rect(sx, statsY, statW - 8, 60)
      .lineWidth(0.5)
      .stroke();

    const { r: cr, g: cg, b: cb } = hexToRgb(stat.color);
    setColor(doc, stat.color);
    doc.fontSize(24).font("Helvetica-Bold");
    doc.text(stat.val.toString(), sx + 8, statsY + 8);

    setColor(doc, COLORS.textDim);
    doc.fontSize(9).font("Helvetica");
    doc.text(stat.label.toUpperCase(), sx + 8, statsY + 38);
  });

  // Footer
  setColor(doc, COLORS.textDim);
  doc.fontSize(9).font("Helvetica");
  doc.text(
    "CONFIDENTIAL — This report contains sensitive security information. Handle with care.",
    60,
    doc.page.height - 50,
    { width: doc.page.width - 120, align: "center" },
  );
}

function drawPageHeader(doc, title) {
  drawBackground(doc);
  const { r, g, b } = hexToRgb(COLORS.purple);
  doc.rect(0, 0, doc.page.width, 2).fill([r, g, b]);

  setColor(doc, COLORS.textDim);
  doc.fontSize(8).font("Helvetica");
  doc.text("GHOSTRECON SECURITY REPORT", 60, 20);

  setColor(doc, COLORS.text);
  doc.fontSize(18).font("Helvetica-Bold");
  doc.text(title, 60, 40);

  setStroke(doc, COLORS.border);
  doc
    .moveTo(60, 68)
    .lineTo(doc.page.width - 60, 68)
    .lineWidth(0.5)
    .stroke();
}

function drawPageFooter(doc, pageNum) {
  setStroke(doc, COLORS.border);
  doc
    .moveTo(60, doc.page.height - 40)
    .lineTo(doc.page.width - 60, doc.page.height - 40)
    .lineWidth(0.5)
    .stroke();

  setColor(doc, COLORS.textDim);
  doc.fontSize(8).font("Helvetica");
  doc.text(
    "GhostRecon Security Platform — Confidential",
    60,
    doc.page.height - 28,
  );
  doc.text(`Page ${pageNum}`, doc.page.width - 100, doc.page.height - 28);
}

function drawExecutiveSummary(doc, scan, summary, pageNum) {
  drawPageHeader(doc, "Executive Summary");

  let y = 90;

  // What was tested
  const { r: sr, g: sg, b: sb } = hexToRgb(COLORS.surface);
  doc.rect(60, y, doc.page.width - 120, 80).fill([sr, sg, sb]);
  setStroke(doc, COLORS.border);
  doc
    .rect(60, y, doc.page.width - 120, 80)
    .lineWidth(0.5)
    .stroke();

  setColor(doc, COLORS.textDim);
  doc.fontSize(9).font("Helvetica");
  doc.text("ASSESSMENT TARGET", 80, y + 12);

  setColor(doc, COLORS.text);
  doc.fontSize(13).font("Helvetica-Bold");
  doc.text(scan.target, 80, y + 26, { width: doc.page.width - 160 });

  setColor(doc, COLORS.textMuted);
  doc.fontSize(10).font("Helvetica");
  doc.text(
    `Scan completed on ${new Date(scan.scanned_at).toLocaleString()}`,
    80,
    y + 50,
  );
  doc.text(
    `${scan.result?.pagesScanned || 0} pages scanned · ${scan.result?.formsFound || 0} forms tested`,
    80,
    y + 63,
  );

  y += 100;

  // Plain English summary
  setColor(doc, COLORS.text);
  doc.fontSize(13).font("Helvetica-Bold");
  doc.text("Summary", 60, y);
  y += 20;

  const riskScore = scan.result?.riskScore || 0;
  const riskLevel =
    riskScore >= 70
      ? "critical"
      : riskScore >= 40
        ? "moderate"
        : riskScore >= 10
          ? "low"
          : "minimal";

  let summaryText = `This security assessment of ${scan.target} identified ${summary.total} security issues across ${scan.result?.pagesScanned || 0} pages. `;

  if (summary.critical > 0) {
    summaryText += `${summary.critical} critical vulnerabilities were found that require immediate attention. These represent significant risks to your application and user data. `;
  }
  if (summary.high > 0) {
    summaryText += `${summary.high} high severity issues were identified that should be addressed as a priority. `;
  }
  if (summary.medium > 0) {
    summaryText += `${summary.medium} medium severity issues were found that should be resolved in the near term. `;
  }
  if (summary.total === 0) {
    summaryText = `This security assessment of ${scan.target} found no significant vulnerabilities. The application appears to be well configured. Regular security assessments are still recommended.`;
  }

  setColor(doc, COLORS.textMuted);
  doc.fontSize(11).font("Helvetica");
  doc.text(summaryText, 60, y, { width: doc.page.width - 120, lineGap: 4 });

  y += doc.heightOfString(summaryText, { width: doc.page.width - 120 }) + 30;

  // Risk breakdown chart
  setColor(doc, COLORS.text);
  doc.fontSize(13).font("Helvetica-Bold");
  doc.text("Risk Breakdown", 60, y);
  y += 20;

  const severities = [
    { label: "Critical", val: summary.critical, color: COLORS.critical },
    { label: "High", val: summary.high, color: COLORS.high },
    { label: "Medium", val: summary.medium, color: COLORS.medium },
    { label: "Low", val: summary.low, color: COLORS.low },
    { label: "Info", val: summary.info || 0, color: COLORS.info },
  ];

  const maxVal = Math.max(...severities.map((s) => s.val), 1);
  const barMaxW = doc.page.width - 220;

  severities.forEach((sev) => {
    const barW = (sev.val / maxVal) * barMaxW;
    const { r: bgr, g: bgg, b: bgb } = hexToRgb("#1e1e22");
    doc.rect(140, y, barMaxW, 18).fill([bgr, bgg, bgb]);

    if (barW > 0) {
      const { r: cr, g: cg, b: cb } = hexToRgb(sev.color);
      doc.rect(140, y, barW, 18).fill([cr, cg, cb]);
    }

    setColor(doc, COLORS.textMuted);
    doc.fontSize(10).font("Helvetica");
    doc.text(sev.label, 60, y + 3, { width: 75 });

    setColor(doc, sev.val > 0 ? COLORS.text : COLORS.textDim);
    doc.fontSize(10).font("Helvetica-Bold");
    doc.text(sev.val.toString(), 140 + barMaxW + 10, y + 3);

    y += 26;
  });

  y += 20;

  pageNum = drawComplianceSection(
    doc,
    scan.result?.findings || scan.result?.vulnerabilities || [],
    pageNum,
  );

  drawPageFooter(doc, pageNum);
}

function drawComplianceSection(doc, findings, pageNum) {
  drawPageHeader(doc, "Compliance Assessment");
  let y = 90;

  const frameworks = [
    {
      name: "OWASP Top 10 2021",
      color: COLORS.purple,
      items: [
        {
          code: "A01",
          name: "Broken Access Control",
          keywords: ["access control", "idor", "csrf", "cors", "open redirect"],
        },
        {
          code: "A02",
          name: "Cryptographic Failures",
          keywords: [
            "ssl",
            "tls",
            "hsts",
            "cryptographic",
            "jwt",
            "cookie secure",
          ],
        },
        {
          code: "A03",
          name: "Injection",
          keywords: [
            "sql injection",
            "xss",
            "injection",
            "ssti",
            "ssrf",
            "xxe",
          ],
        },
        {
          code: "A04",
          name: "Insecure Design",
          keywords: ["rate limiting", "brute force", "mass assignment"],
        },
        {
          code: "A05",
          name: "Security Misconfiguration",
          keywords: [
            "misconfiguration",
            "server version",
            "header",
            "waf",
            "admin",
          ],
        },
        {
          code: "A06",
          name: "Vulnerable Components",
          keywords: ["cve", "outdated", "wordpress", "plugin"],
        },
        {
          code: "A07",
          name: "Auth Failures",
          keywords: ["authentication", "jwt", "weak credentials", "login"],
        },
        {
          code: "A08",
          name: "Data Integrity Failures",
          keywords: ["integrity", "deserialization"],
        },
        {
          code: "A09",
          name: "Logging Failures",
          keywords: ["logging", "monitoring", "verbose error"],
        },
        {
          code: "A10",
          name: "SSRF",
          keywords: ["ssrf", "server-side request"],
        },
      ],
    },
    {
      name: "PCI-DSS Requirements",
      color: COLORS.high,
      items: [
        {
          code: "PCI 2.2",
          name: "System Configuration",
          keywords: ["server version", "misconfiguration", "default"],
        },
        {
          code: "PCI 4.1",
          name: "Encrypt Transmission",
          keywords: ["ssl", "tls", "hsts", "https", "certificate"],
        },
        {
          code: "PCI 6.3",
          name: "Secure Development",
          keywords: ["sql injection", "xss", "injection", "csrf"],
        },
        {
          code: "PCI 6.4",
          name: "Common Vulnerabilities",
          keywords: ["injection", "xss", "broken auth"],
        },
        {
          code: "PCI 7.1",
          name: "Restrict Access",
          keywords: ["admin panel", "access control", "idor"],
        },
        {
          code: "PCI 8.2",
          name: "Authentication",
          keywords: [
            "authentication",
            "jwt",
            "weak credentials",
            "rate limiting",
          ],
        },
      ],
    },
    {
      name: "ISO 27001 Controls",
      color: COLORS.medium,
      items: [
        {
          code: "A.9.1",
          name: "Access Control Policy",
          keywords: ["access control", "idor", "broken access"],
        },
        {
          code: "A.10.1",
          name: "Cryptographic Controls",
          keywords: ["ssl", "tls", "cryptographic", "https", "jwt"],
        },
        {
          code: "A.14.1",
          name: "Security Requirements",
          keywords: ["sql injection", "xss", "injection", "csrf", "ssrf"],
        },
        {
          code: "A.14.2",
          name: "Security in Development",
          keywords: ["xss", "injection", "stored xss"],
        },
        {
          code: "A.12.6",
          name: "Technical Vulnerabilities",
          keywords: ["cve", "vulnerable", "outdated"],
        },
        {
          code: "A.16.1",
          name: "Incident Management",
          keywords: ["error disclosure", "stack trace", "verbose"],
        },
      ],
    },
  ];

  frameworks.forEach((framework) => {
    if (y + 200 > doc.page.height - 60) {
      drawPageFooter(doc, pageNum);
      pageNum++;
      doc.addPage();
      drawPageHeader(doc, "Compliance Assessment (continued)");
      y = 90;
    }

    // Framework header
    const { r: fr, g: fg, b: fb } = hexToRgb(framework.color);
    doc.rect(60, y, doc.page.width - 120, 24).fill([fr, fg, fb]);
    setColor(doc, COLORS.white);
    doc.fontSize(11).font("Helvetica-Bold");
    doc.text(framework.name, 70, y + 7);

    // Calculate score
    const passed = framework.items.filter((item) => {
      const findingText = findings
        .map((f) => `${f.type} ${f.detail || ""}`)
        .join(" ")
        .toLowerCase();
      return !item.keywords.some((kw) =>
        findingText.includes(kw.toLowerCase()),
      );
    }).length;
    const score = Math.round((passed / framework.items.length) * 100);

    setColor(doc, COLORS.white);
    doc.fontSize(11).font("Helvetica-Bold");
    doc.text(`${score}% Compliant`, doc.page.width - 160, y + 7);
    y += 24;

    // Items
    framework.items.forEach((item, i) => {
      const findingText = findings
        .map((f) => `${f.type} ${f.detail || ""}`)
        .join(" ")
        .toLowerCase();
      const failed = item.keywords.some((kw) =>
        findingText.includes(kw.toLowerCase()),
      );

      const { r: sr, g: sg, b: sb } = hexToRgb(COLORS.surface);
      doc.rect(60, y, doc.page.width - 120, 22).fill([sr, sg, sb]);

      if (failed) {
        const { r: cr, g: cg, b: cb } = hexToRgb(COLORS.high);
        doc.rect(60, y, 3, 22).fill([cr, cg, cb]);
      } else {
        const { r: cr, g: cg, b: cb } = hexToRgb(COLORS.green);
        doc.rect(60, y, 3, 22).fill([cr, cg, cb]);
      }

      setColor(doc, COLORS.textDim);
      doc.fontSize(8).font("Helvetica");
      doc.text(item.code, 70, y + 7);

      setColor(doc, COLORS.textMuted);
      doc.fontSize(9).font("Helvetica");
      doc.text(item.name, 130, y + 7);

      setColor(doc, failed ? COLORS.high : COLORS.green);
      doc.fontSize(8).font("Helvetica-Bold");
      doc.text(failed ? "FAIL" : "PASS", doc.page.width - 80, y + 7);

      y += 23;
    });

    // Score bar
    y += 8;
    const barW = doc.page.width - 120;
    const { r: bgr, g: bgg, b: bgb } = hexToRgb("#1e1e22");
    doc.rect(60, y, barW, 8).fill([bgr, bgg, bgb]);
    const scoreColor =
      score >= 80 ? COLORS.green : score >= 50 ? COLORS.medium : COLORS.high;
    const { r: scr, g: scg, b: scb } = hexToRgb(scoreColor);
    doc.rect(60, y, (score / 100) * barW, 8).fill([scr, scg, scb]);

    setColor(doc, scoreColor);
    doc.fontSize(9).font("Helvetica-Bold");
    doc.text(`${score}%`, 60 + (score / 100) * barW + 5, y);

    y += 30;
  });

  drawPageFooter(doc, pageNum);
  return pageNum;
}

function drawFindingsPage(doc, findings, pageNum) {
  drawPageHeader(doc, "Detailed Findings");
  let y = 90;

  if (findings.length === 0) {
    setColor(doc, COLORS.green);
    doc.fontSize(14).font("Helvetica-Bold");
    doc.text("No vulnerabilities found.", 60, y);
    setColor(doc, COLORS.textMuted);
    doc.fontSize(11).font("Helvetica");
    doc.text(
      "The security assessment completed without finding significant vulnerabilities.",
      60,
      y + 25,
    );
    drawPageFooter(doc, pageNum);
    return pageNum;
  }

  const sortedFindings = [...findings].sort((a, b) => {
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return (order[a.severity] || 5) - (order[b.severity] || 5);
  });

  sortedFindings.forEach((finding, i) => {
    const severityColor = getSeverityColor(finding.severity);

    // Estimate height needed
    const detailH = finding.detail
      ? doc.heightOfString(finding.detail, {
          width: doc.page.width - 160,
          fontSize: 10,
        })
      : 0;
    const evidenceH = finding.evidence ? 30 : 0;
    const remediationH = finding.remediation
      ? doc.heightOfString(finding.remediation, {
          width: doc.page.width - 160,
          fontSize: 10,
        }) + 20
      : 0;
    const totalH = 80 + detailH + evidenceH + remediationH + 20;

    // New page if needed
    if (y + totalH > doc.page.height - 60) {
      drawPageFooter(doc, pageNum);
      pageNum++;
      doc.addPage();
      drawPageHeader(doc, "Detailed Findings (continued)");
      y = 90;
    }

    // Finding card background
    const { r: sr, g: sg, b: sb } = hexToRgb(COLORS.surface);
    doc.rect(60, y, doc.page.width - 120, totalH).fill([sr, sg, sb]);
    setStroke(doc, COLORS.border);
    doc
      .rect(60, y, doc.page.width - 120, totalH)
      .lineWidth(0.5)
      .stroke();

    // Severity left bar
    const { r: cr, g: cg, b: cb } = hexToRgb(severityColor);
    doc.rect(60, y, 4, totalH).fill([cr, cg, cb]);

    // Finding number
    setColor(doc, COLORS.textDim);
    doc.fontSize(8).font("Helvetica");
    doc.text(`#${i + 1}`, 75, y + 10);

    // Severity badge
    doc.rect(95, y + 7, 55, 14).fill([cr, cg, cb]);
    setColor(doc, COLORS.white);
    doc.fontSize(7).font("Helvetica-Bold");
    doc.text(finding.severity.toUpperCase(), 97, y + 11);

    // OWASP badge
    if (finding.owasp) {
      const { r: pr, g: pg, b: pb } = hexToRgb("#0d0d2e");
      doc.rect(158, y + 7, 130, 14).fill([pr, pg, pb]);
      setColor(doc, COLORS.purple);
      doc.fontSize(7).font("Helvetica");
      doc.text(finding.owasp.substring(0, 25), 161, y + 11);
    }

    // Title
    setColor(doc, COLORS.text);
    doc.fontSize(12).font("Helvetica-Bold");
    doc.text(finding.type, 75, y + 28, { width: doc.page.width - 150 });

    let contentY = y + 50;

    // Endpoint
    if (finding.endpoint) {
      setColor(doc, COLORS.textDim);
      doc.fontSize(8).font("Helvetica");
      doc.text(`${finding.method || "GET"} ${finding.endpoint}`, 75, contentY, {
        width: doc.page.width - 150,
      });
      contentY += 14;
    }

    // Detail
    if (finding.detail) {
      setColor(doc, COLORS.textMuted);
      doc.fontSize(10).font("Helvetica");
      doc.text(finding.detail, 75, contentY, {
        width: doc.page.width - 150,
        lineGap: 2,
      });
      contentY += detailH + 8;
    }

    // Evidence
    if (finding.evidence) {
      const { r: bgr, g: bgg, b: bgb } = hexToRgb("#0d0d0f");
      doc.rect(75, contentY, doc.page.width - 150, 22).fill([bgr, bgg, bgb]);
      setColor(doc, COLORS.textDim);
      doc.fontSize(8).font("Helvetica");
      const evidenceText =
        finding.evidence.length > 100
          ? finding.evidence.substring(0, 100) + "..."
          : finding.evidence;
      doc.text(`Evidence: ${evidenceText}`, 80, contentY + 7, {
        width: doc.page.width - 160,
      });
      contentY += 28;
    }

    // Remediation
    if (finding.remediation) {
      const { r: gr, g: gg, b: gb } = hexToRgb("#0a1a14");
      doc
        .rect(75, contentY, doc.page.width - 150, remediationH)
        .fill([gr, gg, gb]);
      const { r: glr, g: glg, b: glb } = hexToRgb(COLORS.green);
      doc.rect(75, contentY, 2, remediationH).fill([glr, glg, glb]);
      setColor(doc, COLORS.green);
      doc.fontSize(9).font("Helvetica-Bold");
      doc.text("Remediation:", 82, contentY + 6);
      setColor(doc, COLORS.textMuted);
      doc.fontSize(10).font("Helvetica");
      doc.text(finding.remediation, 82, contentY + 18, {
        width: doc.page.width - 164,
        lineGap: 2,
      });
    }

    y += totalH + 12;
  });

  drawPageFooter(doc, pageNum);
  return pageNum;
}

function drawRemediationSummary(doc, findings, pageNum) {
  drawPageHeader(doc, "Remediation Summary");
  let y = 90;

  setColor(doc, COLORS.textMuted);
  doc.fontSize(11).font("Helvetica");
  doc.text(
    "Address vulnerabilities in this order based on severity and impact:",
    60,
    y,
    { width: doc.page.width - 120 },
  );
  y += 30;

  const priorityGroups = [
    {
      label: "IMMEDIATE ACTION REQUIRED",
      severities: ["Critical"],
      color: COLORS.critical,
      timeframe: "Fix within 24 hours",
    },
    {
      label: "HIGH PRIORITY",
      severities: ["High"],
      color: COLORS.high,
      timeframe: "Fix within 1 week",
    },
    {
      label: "MEDIUM PRIORITY",
      severities: ["Medium"],
      color: COLORS.medium,
      timeframe: "Fix within 1 month",
    },
    {
      label: "LOW PRIORITY",
      severities: ["Low", "Info"],
      color: COLORS.low,
      timeframe: "Fix within 3 months",
    },
  ];

  priorityGroups.forEach((group) => {
    const groupFindings = findings.filter((f) =>
      group.severities.includes(f.severity),
    );
    if (groupFindings.length === 0) return;

    if (y > doc.page.height - 100) {
      drawPageFooter(doc, pageNum);
      pageNum++;
      doc.addPage();
      drawPageHeader(doc, "Remediation Summary (continued)");
      y = 90;
    }

    const { r: cr, g: cg, b: cb } = hexToRgb(group.color);
    doc.rect(60, y, doc.page.width - 120, 24).fill([cr, cg, cb]);
    setColor(doc, COLORS.white);
    doc.fontSize(10).font("Helvetica-Bold");
    doc.text(group.label, 70, y + 7);
    doc.text(group.timeframe, doc.page.width - 180, y + 7);
    y += 24;

    groupFindings.forEach((finding, i) => {
      if (y > doc.page.height - 80) {
        drawPageFooter(doc, pageNum);
        pageNum++;
        doc.addPage();
        drawPageHeader(doc, "Remediation Summary (continued)");
        y = 90;
      }

      const { r: sr, g: sg, b: sb } = hexToRgb(COLORS.surface);
      doc.rect(60, y, doc.page.width - 120, 50).fill([sr, sg, sb]);
      setStroke(doc, COLORS.border);
      doc
        .rect(60, y, doc.page.width - 120, 50)
        .lineWidth(0.5)
        .stroke();

      setColor(doc, COLORS.textDim);
      doc.fontSize(8).font("Helvetica");
      doc.text(`${i + 1}.`, 72, y + 8);

      setColor(doc, COLORS.text);
      doc.fontSize(11).font("Helvetica-Bold");
      doc.text(finding.type, 85, y + 8, { width: doc.page.width - 170 });

      setColor(doc, COLORS.green);
      doc.fontSize(9).font("Helvetica");
      const rem =
        finding.remediation || "See detailed findings for remediation steps.";
      const remText = rem.length > 120 ? rem.substring(0, 120) + "..." : rem;
      doc.text(remText, 85, y + 26, { width: doc.page.width - 150 });

      y += 56;
    });
    y += 10;
  });

  drawPageFooter(doc, pageNum);
  return pageNum;
}

// Get all scans
router.get("/scans", async (req, res) => {
  try {
    const query = req.user.role === "admin" ? {} : { userId: req.user.id };
    const scans = await scansDb.find(query).sort({ scanned_at: -1 }).limit(50);
    res.json({ success: true, scans });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Generate PDF report
router.post("/generate", async (req, res) => {
  const { scanId } = req.body;
  if (!scanId) return res.status(400).json({ error: "Scan ID is required." });

  try {
    const scan = await scansDb.findOne({ _id: scanId });
    if (!scan) return res.status(404).json({ error: "Scan not found." });

    const result = scan.result || {};
    const findings = result.findings || result.vulnerabilities || [];

    const summary = {
      critical: findings.filter((f) => f.severity === "Critical").length,
      high: findings.filter((f) => f.severity === "High").length,
      medium: findings.filter((f) => f.severity === "Medium").length,
      low: findings.filter((f) => f.severity === "Low").length,
      info: findings.filter((f) => f.severity === "Info").length,
      total: findings.length,
    };

    // Set up PDF
    const doc = new PDFDocument({
      size: "A4",
      margin: 0,
      bufferPages: true,
      info: {
        Title: `GhostRecon Security Report — ${scan.target}`,
        Author: "GhostRecon Security Platform",
        Subject: "Web Application Security Assessment",
        Keywords: "security, penetration testing, vulnerability assessment",
      },
    });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="GhostRecon-Report-${scan.target.replace(/[^a-z0-9]/gi, "-")}-${Date.now()}.pdf"`,
    );
    doc.pipe(res);

    let pageNum = 1;

    // Page 1 — Cover
    drawCoverPage(doc, scan, summary);
    drawPageFooter(doc, pageNum);

    // Page 2 — Executive Summary
    pageNum++;
    doc.addPage();
    drawExecutiveSummary(doc, scan, summary, pageNum);

    // Page 3+ — Detailed Findings
    pageNum++;
    doc.addPage();
    pageNum = drawFindingsPage(doc, findings, pageNum);

    // Final page — Remediation Summary
    pageNum++;
    doc.addPage();
    pageNum = drawRemediationSummary(doc, findings, pageNum);

    // Add compliance page
    pageNum++;
    doc.addPage();
    pageNum = drawComplianceSection(doc, findings, pageNum);

    doc.end();
  } catch (err) {
    console.error("PDF error:", err);
    if (!res.headersSent) {
      res.status(500).json({ error: "PDF generation failed: " + err.message });
    }
  }
});

module.exports = router;
