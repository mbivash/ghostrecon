const express = require("express");
const router = express.Router();
const PDFDocument = require("pdfkit");

router.post("/generate", (req, res) => {
  const { clientName, reportTitle, scans, analystName } = req.body;

  if (!scans || scans.length === 0) {
    return res.status(400).json({ error: "No scan data provided." });
  }

  // Set response headers for PDF download
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="ghostrecon-report-${Date.now()}.pdf"`,
  );

  const doc = new PDFDocument({ margin: 50, size: "A4", bufferPages: true });
  doc.pipe(res);

  const colors = {
    bg: "#0d0d0f",
    purple: "#7F77DD",
    red: "#E24B4A",
    amber: "#BA7517",
    green: "#1D9E75",
    text: "#1a1a1a",
    muted: "#666666",
    border: "#e0e0e0",
  };

  const pageWidth = doc.page.width - 100;

  // ── Cover Page ──────────────────────────────────────
  // Header bar
  doc.rect(0, 0, doc.page.width, 180).fill("#0d0d0f");

  // GhostRecon logo text
  doc
    .fontSize(28)
    .fillColor("#7F77DD")
    .text("Ghost", 50, 60, { continued: true });
  doc.fillColor("#e8e6f0").text("Recon");

  doc
    .fontSize(11)
    .fillColor("#555555")
    .text("Ethical Hacking Platform", 50, 98);

  // Report title
  doc
    .fontSize(18)
    .fillColor("#e8e6f0")
    .text(reportTitle || "Security Assessment Report", 50, 125);

  // Date line
  doc.moveDown(4);
  doc.rect(0, 180, doc.page.width, 1).fill("#1e1e22");

  // Report meta
  doc.moveDown(2);
  doc.fontSize(12).fillColor(colors.text);

  const meta = [
    ["Client", clientName || "Confidential"],
    ["Analyst", analystName || "GhostRecon Analyst"],
    [
      "Date",
      new Date().toLocaleDateString("en-IN", {
        year: "numeric",
        month: "long",
        day: "numeric",
      }),
    ],
    ["Classification", "CONFIDENTIAL"],
    ["Total Scans", scans.length.toString()],
  ];

  let metaY = 220;
  meta.forEach(([label, value]) => {
    doc.fontSize(10).fillColor(colors.muted).text(label, 50, metaY);
    doc.fontSize(11).fillColor(colors.text).text(value, 200, metaY);
    metaY += 24;
  });

  // Total vulnerabilities count
  let totalVulns = 0;
  let critical = 0,
    high = 0,
    medium = 0,
    low = 0;

  scans.forEach((scan) => {
    if (scan.vulnerabilities) {
      totalVulns += scan.vulnerabilities.length;
      scan.vulnerabilities.forEach((v) => {
        if (v.severity === "Critical") critical++;
        else if (v.severity === "High") high++;
        else if (v.severity === "Medium") medium++;
        else low++;
      });
    }
    if (scan.ports) {
      totalVulns += scan.ports.length;
    }
  });

  // Summary boxes
  const boxY = 380;
  const boxW = 100;
  const boxH = 70;
  const boxes = [
    { label: "Critical", val: critical, color: "#E24B4A" },
    { label: "High", val: high, color: "#E24B4A" },
    { label: "Medium", val: medium, color: "#BA7517" },
    { label: "Low", val: low, color: "#639922" },
  ];

  boxes.forEach((box, i) => {
    const bx = 50 + i * (boxW + 16);
    doc.rect(bx, boxY, boxW, boxH).stroke(box.color);
    doc
      .fontSize(24)
      .fillColor(box.color)
      .text(box.val.toString(), bx, boxY + 12, {
        width: boxW,
        align: "center",
      });
    doc
      .fontSize(10)
      .fillColor(colors.muted)
      .text(box.label, bx, boxY + 46, { width: boxW, align: "center" });
  });

  // Disclaimer
  doc.rect(50, 490, pageWidth, 50).fill("#fff8f0");
  doc.rect(50, 490, 3, 50).fill(colors.amber);
  doc.fontSize(9).fillColor(colors.amber).text("LEGAL DISCLAIMER", 62, 498);
  doc
    .fontSize(8)
    .fillColor("#666")
    .text(
      "This report is confidential and intended solely for the authorized recipient. All testing was performed with explicit written authorization.",
      62,
      510,
      { width: pageWidth - 20 },
    );

  // ── Page 2: Executive Summary ───────────────────────
  doc.addPage();

  sectionHeader(doc, "Executive Summary", colors);

  doc.fontSize(11).fillColor(colors.text).moveDown(0.5);
  doc.text(
    `This security assessment was conducted on ${new Date().toLocaleDateString()} for ${clientName || "the client"}. ` +
      `A total of ${scans.length} scan(s) were performed across the target infrastructure. ` +
      `The assessment identified ${totalVulns} findings across all tested systems.`,
    { width: pageWidth, lineGap: 4 },
  );

  doc.moveDown(1);

  if (critical + high > 0) {
    doc
      .fontSize(11)
      .fillColor(colors.red)
      .text(
        `Critical attention required: ${critical + high} high-severity finding(s) require immediate remediation.`,
        {
          width: pageWidth,
          lineGap: 4,
        },
      );
  } else {
    doc
      .fontSize(11)
      .fillColor(colors.green)
      .text("No critical or high severity vulnerabilities were found.", {
        width: pageWidth,
      });
  }

  doc.moveDown(1.5);
  sectionHeader(doc, "Scope of Assessment", colors);
  scans.forEach((scan, i) => {
    doc
      .fontSize(10)
      .fillColor(colors.text)
      .text(
        `${i + 1}. ${scan.target || scan.url || "Unknown target"} — ${scan.type || "Security scan"}`,
        {
          width: pageWidth,
        },
      );
  });

  // ── Page 3+: Detailed Findings ──────────────────────
  scans.forEach((scan, scanIndex) => {
    doc.addPage();

    sectionHeader(
      doc,
      `Finding ${scanIndex + 1}: ${scan.type || "Scan Result"}`,
      colors,
    );

    doc
      .fontSize(10)
      .fillColor(colors.muted)
      .text("Target", { continued: true });
    doc.fillColor(colors.text).text(`  ${scan.target || scan.url || "N/A"}`);
    doc
      .fontSize(10)
      .fillColor(colors.muted)
      .text("Scan date", { continued: true });
    doc
      .fillColor(colors.text)
      .text(`  ${new Date(scan.scannedAt || Date.now()).toLocaleString()}`);

    doc.moveDown(1);

    // Network scan — ports table
    if (scan.ports && scan.ports.length > 0) {
      doc
        .fontSize(11)
        .fillColor(colors.text)
        .text("Open Ports", { underline: true });
      doc.moveDown(0.5);

      const colW = [80, 80, 80, pageWidth - 240];
      const headers = ["Port", "Protocol", "State", "Service"];
      let tableY = doc.y;

      // Table header
      doc.rect(50, tableY, pageWidth, 22).fill("#f5f5f5");
      headers.forEach((h, i) => {
        const x = 50 + colW.slice(0, i).reduce((a, b) => a + b, 0);
        doc
          .fontSize(9)
          .fillColor(colors.muted)
          .text(h, x + 6, tableY + 7, { width: colW[i] });
      });
      tableY += 22;

      scan.ports.forEach((port, pi) => {
        if (pi % 2 === 0) doc.rect(50, tableY, pageWidth, 20).fill("#fafafa");
        const row = [port.port, port.protocol, port.state, port.service];
        row.forEach((cell, i) => {
          const x = 50 + colW.slice(0, i).reduce((a, b) => a + b, 0);
          doc
            .fontSize(9)
            .fillColor(colors.text)
            .text(String(cell || ""), x + 6, tableY + 6, {
              width: colW[i] - 6,
            });
        });
        tableY += 20;
      });

      doc.y = tableY + 10;
    }

    // Web vuln scan — vulnerability list
    if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
      doc
        .fontSize(11)
        .fillColor(colors.text)
        .text("Vulnerabilities Found", { underline: true });
      doc.moveDown(0.5);

      scan.vulnerabilities.forEach((vuln, vi) => {
        if (doc.y > 700) doc.addPage();

        const sevColor =
          {
            Critical: colors.red,
            High: colors.red,
            Medium: colors.amber,
            Low: colors.green,
          }[vuln.severity] || colors.muted;

        doc.rect(50, doc.y, 3, 52).fill(sevColor);
        doc.fontSize(10).fillColor(sevColor).text(vuln.severity, 62, doc.y);
        doc
          .fontSize(10)
          .fillColor(colors.text)
          .text(vuln.type, 110, doc.y - 12);
        doc.moveDown(0.3);
        doc
          .fontSize(9)
          .fillColor(colors.muted)
          .text(vuln.detail, 62, doc.y, { width: pageWidth - 20 });
        doc.moveDown(0.3);
        doc
          .fontSize(8)
          .fillColor("#aaa")
          .text(`Evidence: ${vuln.evidence}`, 62, doc.y, {
            width: pageWidth - 20,
          });
        doc.moveDown(1);
      });
    }

    if (
      (!scan.ports || scan.ports.length === 0) &&
      (!scan.vulnerabilities || scan.vulnerabilities.length === 0)
    ) {
      doc
        .fontSize(11)
        .fillColor(colors.green)
        .text("No issues found in this scan.");
    }
  });

  // ── Final Page: Recommendations ────────────────────
  doc.addPage();
  sectionHeader(doc, "Recommendations", colors);

  const recs = [];
  scans.forEach((scan) => {
    if (scan.vulnerabilities) {
      scan.vulnerabilities.forEach((v) => {
        if (
          v.type.includes("Content-Security-Policy") ||
          v.type.includes("CSP")
        ) {
          recs.push({
            priority: "High",
            action:
              "Implement a Content Security Policy header to prevent XSS attacks.",
          });
        }
        if (v.type.includes("HSTS")) {
          recs.push({
            priority: "High",
            action:
              "Enable HTTP Strict Transport Security (HSTS) to enforce HTTPS.",
          });
        }
        if (v.type.includes("X-Frame")) {
          recs.push({
            priority: "Medium",
            action:
              "Add X-Frame-Options header to prevent clickjacking attacks.",
          });
        }
        if (v.type.includes("SQL")) {
          recs.push({
            priority: "Critical",
            action:
              "Fix SQL injection vulnerability immediately. Use parameterized queries.",
          });
        }
        if (v.type.includes("XSS")) {
          recs.push({
            priority: "High",
            action:
              "Sanitize all user inputs and encode outputs to prevent XSS.",
          });
        }
        if (v.type.includes("Server Version")) {
          recs.push({
            priority: "Low",
            action:
              "Hide server version information from HTTP response headers.",
          });
        }
      });
    }
  });

  if (recs.length === 0) {
    recs.push({
      priority: "Low",
      action:
        "Continue regular security assessments to maintain security posture.",
    });
  }

  // Remove duplicates
  const uniqueRecs = recs.filter(
    (r, i, arr) => arr.findIndex((x) => x.action === r.action) === i,
  );

  uniqueRecs.forEach((rec, i) => {
    if (doc.y > 700) doc.addPage();
    const sevColor =
      {
        Critical: colors.red,
        High: colors.red,
        Medium: colors.amber,
        Low: colors.green,
      }[rec.priority] || colors.muted;
    doc
      .fontSize(10)
      .fillColor(sevColor)
      .text(`[${rec.priority}]`, 50, doc.y, { continued: true, width: 80 });
    doc
      .fillColor(colors.text)
      .text(` ${rec.action}`, { width: pageWidth - 80 });
    doc.moveDown(0.7);
  });

  // ── Footer on every page ────────────────────────────
  const pageCount = doc.bufferedPageRange().count;
  for (let i = 0; i < pageCount; i++) {
    doc.switchToPage(i);
    doc
      .fontSize(8)
      .fillColor("#aaa")
      .text(
        `GhostRecon Security Report — Confidential — Page ${i + 1} of ${pageCount}`,
        50,
        doc.page.height - 40,
        { width: pageWidth, align: "center" },
      );
  }

  doc.end();
});

function sectionHeader(doc, title, colors) {
  doc.fontSize(14).fillColor(colors.purple).text(title);
  doc.moveDown(0.2);
  doc.rect(50, doc.y, 500, 1).fill(colors.purple);
  doc.moveDown(0.8);
}

module.exports = router;
