// ═══════════════════════════════════════════════════════
// GhostRecon — Professional Validator Module
// Fixes false positives with content validation,
// secret verification, and confidence scoring
// ═══════════════════════════════════════════════════════

const axios = require("axios");

const axiosInstance = axios.create({
  timeout: 10000,
  validateStatus: () => true,
});

// ── Confidence Levels ─────────────────────────────────
const CONFIDENCE = {
  CONFIRMED: "Confirmed",      // Tool verified with secondary check
  PROBABLE: "Probable",        // Strong indicators, manual verify recommended
  POSSIBLE: "Possible",        // Pattern match only, likely needs investigation
};

// ── Sensitive File Validator ──────────────────────────
// Fixes the backup.zip / database.sql false positive problem
async function validateSensitiveFile(url, fileType) {
  try {
    const response = await axiosInstance.get(url, {
      responseType: "arraybuffer",
      timeout: 8000,
    });

    if (response.status !== 200) {
      return { valid: false, reason: `HTTP ${response.status}` };
    }

    const contentType = (response.headers["content-type"] || "").toLowerCase();
    const contentLength = parseInt(response.headers["content-length"] || "0");
    const bodyBuffer = Buffer.from(response.data);
    const bodyText = bodyBuffer.slice(0, 500).toString("utf8", 0, 500);
    const bodySize = bodyBuffer.length;

    // If it's serving HTML — it's a fake/error page, not a real file
    if (contentType.includes("text/html")) {
      return { valid: false, reason: "Response is HTML (error page or WAF intercept)" };
    }

    // Check file signatures (magic bytes)
    const fileChecks = {
      ".zip": {
        magic: [0x50, 0x4b, 0x03, 0x04], // PK\x03\x04
        minSize: 100,
        contentTypes: ["application/zip", "application/octet-stream"],
      },
      ".sql": {
        keywords: ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "ALTER TABLE", "--"],
        minSize: 50,
      },
      ".php": {
        keywords: ["<?php", "<?PHP", "define(", "require("],
        minSize: 10,
      },
      ".env": {
        keywords: ["DB_PASSWORD", "APP_KEY", "SECRET", "DATABASE_URL", "API_KEY"],
        minSize: 10,
      },
      ".git/config": {
        keywords: ["[core]", "[remote", "repositoryformatversion"],
        minSize: 20,
      },
      "phpinfo.php": {
        keywords: ["PHP Version", "php.ini", "phpinfo()"],
        minSize: 100,
      },
    };

    const ext = Object.keys(fileChecks).find((k) => url.includes(k));

    if (ext && fileChecks[ext]) {
      const check = fileChecks[ext];

      // Size check
      if (bodySize < check.minSize) {
        return { valid: false, reason: `Too small (${bodySize} bytes) to be a real ${ext} file` };
      }

      // Magic bytes check for zip
      if (check.magic) {
        const magic = check.magic;
        const matches = magic.every((byte, i) => bodyBuffer[i] === byte);
        if (!matches) {
          return { valid: false, reason: "File magic bytes don't match — not a real ZIP" };
        }
        return {
          valid: true,
          confidence: CONFIDENCE.CONFIRMED,
          size: bodySize,
          reason: `Real ZIP file confirmed (${bodySize} bytes, valid magic bytes)`,
        };
      }

      // Keyword check for text files
      if (check.keywords) {
        const found = check.keywords.find((kw) => bodyText.includes(kw));
        if (!found) {
          return { valid: false, reason: `No expected keywords found in ${ext} file` };
        }
        return {
          valid: true,
          confidence: CONFIDENCE.CONFIRMED,
          size: bodySize,
          keyword: found,
          reason: `Real ${ext} file confirmed — contains "${found}"`,
        };
      }
    }

    // Generic: if it's large and not HTML, probably real
    if (bodySize > 500 && !contentType.includes("html")) {
      return {
        valid: true,
        confidence: CONFIDENCE.PROBABLE,
        size: bodySize,
        reason: `Non-HTML response with ${bodySize} bytes`,
      };
    }

    return { valid: false, reason: "Could not confirm file contents" };
  } catch (e) {
    return { valid: false, reason: `Request failed: ${e.message}` };
  }
}

// ── Secret Validator ──────────────────────────────────
// Tests if a found secret is actually live/valid
async function validateSecret(secretType, secretValue) {
  // Strip masking if present
  const cleanValue = secretValue.replace(/\.\.\./g, "").trim();

  try {
    switch (secretType) {
      case "AWS Access Key": {
        // Test AWS key by calling STS GetCallerIdentity
        const response = await axiosInstance.get(
          "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
          {
            headers: { Authorization: `AWS4-HMAC-SHA256 Credential=${cleanValue}` },
            timeout: 5000,
          }
        );
        if (response.status === 200) {
          return { valid: true, confidence: CONFIDENCE.CONFIRMED, message: "AWS key is ACTIVE — can authenticate to AWS" };
        }
        return { valid: false, confidence: CONFIDENCE.POSSIBLE, message: "AWS key rejected" };
      }

      case "GitHub Token": {
        const response = await axiosInstance.get("https://api.github.com/user", {
          headers: { Authorization: `token ${cleanValue}` },
          timeout: 5000,
        });
        if (response.status === 200 && response.data.login) {
          return { valid: true, confidence: CONFIDENCE.CONFIRMED, message: `GitHub token ACTIVE — authenticated as: ${response.data.login}` };
        }
        return { valid: false, confidence: CONFIDENCE.POSSIBLE, message: "GitHub token invalid or expired" };
      }

      case "Stripe API Key": {
        const response = await axiosInstance.get("https://api.stripe.com/v1/charges?limit=1", {
          headers: { Authorization: `Bearer ${cleanValue}` },
          timeout: 5000,
        });
        if (response.status === 200) {
          return { valid: true, confidence: CONFIDENCE.CONFIRMED, message: "Stripe key ACTIVE — can access payment data" };
        }
        return { valid: false, confidence: CONFIDENCE.POSSIBLE, message: "Stripe key invalid" };
      }

      case "Slack Token": {
        const response = await axiosInstance.get(
          `https://slack.com/api/auth.test?token=${cleanValue}`,
          { timeout: 5000 }
        );
        if (response.data && response.data.ok) {
          return { valid: true, confidence: CONFIDENCE.CONFIRMED, message: `Slack token ACTIVE — workspace: ${response.data.team}` };
        }
        return { valid: false, confidence: CONFIDENCE.POSSIBLE, message: "Slack token invalid" };
      }

      case "Google API Key": {
        const response = await axiosInstance.get(
          `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${cleanValue}`,
          { timeout: 5000 }
        );
        if (response.status === 200) {
          return { valid: true, confidence: CONFIDENCE.CONFIRMED, message: "Google API key is ACTIVE" };
        }
        return { valid: false, confidence: CONFIDENCE.POSSIBLE, message: "Google key invalid" };
      }

      case "SendGrid API Key": {
        const response = await axiosInstance.get("https://api.sendgrid.com/v3/user/profile", {
          headers: { Authorization: `Bearer ${cleanValue}` },
          timeout: 5000,
        });
        if (response.status === 200) {
          return { valid: true, confidence: CONFIDENCE.CONFIRMED, message: "SendGrid key ACTIVE" };
        }
        return { valid: false, confidence: CONFIDENCE.POSSIBLE, message: "SendGrid key invalid" };
      }

      default:
        // Can't auto-validate this type — mark as needs manual check
        return {
          valid: null,
          confidence: CONFIDENCE.POSSIBLE,
          message: `Cannot auto-validate ${secretType} — manual verification required`,
        };
    }
  } catch (e) {
    return {
      valid: null,
      confidence: CONFIDENCE.POSSIBLE,
      message: `Validation request failed: ${e.message}`,
    };
  }
}

// ── Open Redirect Validator ───────────────────────────
// Checks if redirect actually goes to evil.com or just stays on site
function validateOpenRedirect(locationHeader, targetDomain) {
  if (!locationHeader) return { valid: false, reason: "No Location header" };

  try {
    const redirectUrl = new URL(locationHeader);
    const isExternalRedirect = !redirectUrl.hostname.includes(targetDomain);

    if (isExternalRedirect && locationHeader.includes("evil.com")) {
      return {
        valid: true,
        confidence: CONFIDENCE.CONFIRMED,
        reason: `Redirects to external domain: ${redirectUrl.hostname}`,
      };
    }

    // Redirect stays on same domain — not exploitable
    return {
      valid: false,
      reason: `Redirect stays on ${redirectUrl.hostname} — not exploitable`,
    };
  } catch (e) {
    return { valid: false, reason: "Invalid redirect URL" };
  }
}

// ── XSS Validator ────────────────────────────────────
// Checks if XSS payload actually executed vs just reflected as text
function validateXSSReflection(responseBody, payload) {
  if (!responseBody || !payload) return { valid: false, confidence: CONFIDENCE.POSSIBLE };

  // Check it's not HTML-encoded
  const encoded = responseBody.includes("&lt;") || responseBody.includes("&#");
  if (encoded) {
    return { valid: false, reason: "Payload is HTML-encoded — not exploitable" };
  }

  // Check for actual dangerous reflection
  const dangerousPatterns = [
    /<script[^>]*>.*?<\/script>/i,
    /on\w+\s*=\s*["']?alert/i,
    /javascript:\s*alert/i,
    /<img[^>]+onerror\s*=/i,
    /<svg[^>]+onload\s*=/i,
  ];

  const isDangerous = dangerousPatterns.some((p) => p.test(responseBody));

  if (isDangerous) {
    return {
      valid: true,
      confidence: CONFIDENCE.CONFIRMED,
      reason: "XSS payload reflected in executable context",
    };
  }

  // Payload reflected but not in dangerous context
  if (responseBody.includes(payload)) {
    return {
      valid: true,
      confidence: CONFIDENCE.PROBABLE,
      reason: "Payload reflected — verify manually if executable",
    };
  }

  return { valid: false, reason: "Payload not found in response" };
}

// ── Add Confidence to All Findings ───────────────────
function addConfidenceToFindings(findings) {
  return findings.map((finding) => {
    if (finding.confidence) return finding; // Already has confidence

    // Assign confidence based on finding type
    const confirmedTypes = [
      "SQL Injection",
      "Server-Side Request Forgery",
      "Directory Traversal",
      "Weak/Default Credentials",
      "JWT None Algorithm",
      "Stored XSS Confirmed",
      "CORS Misconfiguration with Credentials",
    ];

    const probableTypes = [
      "Cross-Site Scripting (XSS)",
      "CSRF Token Missing",
      "Cookie Missing HttpOnly",
      "Cookie Missing Secure Flag",
      "Clickjacking Vulnerability",
      "No Login Rate Limiting",
      "IDOR",
    ];

    const possibleTypes = [
      "DOM-Based XSS (Potential)",
      "Dangerous DOM Sink",
      "Missing Security Header",
      "Open Redirect",
      "Secret Exposed",
      "Technology Stack",
      "CMS Detected",
      "WordPress",
      "Backup file",
      "Database dump",
      "PHP config",
    ];

    if (confirmedTypes.some((t) => finding.type.includes(t))) {
      finding.confidence = CONFIDENCE.CONFIRMED;
    } else if (probableTypes.some((t) => finding.type.includes(t))) {
      finding.confidence = CONFIDENCE.PROBABLE;
    } else if (possibleTypes.some((t) => finding.type.includes(t))) {
      finding.confidence = CONFIDENCE.POSSIBLE;
    } else {
      finding.confidence = CONFIDENCE.PROBABLE;
    }

    return finding;
  });
}

// ── Filter False Positives ────────────────────────────
function filterFalsePositives(findings) {
  const filtered = [];
  const falsePositivePatterns = [
    // security.txt is a GOOD thing, not a vulnerability
    (f) => f.type === "Security.txt found",
    // WAF detected is informational — good protection
    (f) => f.type === "WAF Detected",
  ];

  for (const finding of findings) {
    const isFalsePositive = falsePositivePatterns.some((check) => check(finding));
    if (!isFalsePositive) {
      filtered.push(finding);
    }
  }

  return filtered;
}

module.exports = {
  validateSensitiveFile,
  validateSecret,
  validateOpenRedirect,
  validateXSSReflection,
  addConfidenceToFindings,
  filterFalsePositives,
  CONFIDENCE,
};
