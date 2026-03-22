const express = require("express");
const router = express.Router();
const axios = require("axios");
const cheerio = require("cheerio");
const { scansDb } = require("../database");

const axiosInstance = axios.create({
  timeout: 15000,
  validateStatus: () => true,
  headers: {
    "User-Agent": "Mozilla/5.0 (compatible; GhostRecon WordPress Scanner)",
    Accept: "text/html,application/json,*/*",
  },
  maxRedirects: 3,
});

// Known vulnerable plugins database
const VULNERABLE_PLUGINS = [
  {
    slug: "contact-form-7",
    name: "Contact Form 7",
    cve: "CVE-2020-35489",
    severity: "Critical",
    desc: "Unrestricted file upload vulnerability",
  },
  {
    slug: "woocommerce",
    name: "WooCommerce",
    cve: "CVE-2021-32789",
    severity: "High",
    desc: "SQL injection in versions below 5.5.1",
  },
  {
    slug: "yoast-seo",
    name: "Yoast SEO",
    cve: "CVE-2021-25114",
    severity: "Medium",
    desc: "Stored XSS in versions below 15.1.2",
  },
  {
    slug: "elementor",
    name: "Elementor",
    cve: "CVE-2022-29455",
    severity: "High",
    desc: "DOM XSS vulnerability in versions below 3.5.6",
  },
  {
    slug: "wpforms-lite",
    name: "WPForms",
    cve: "CVE-2021-34621",
    severity: "Critical",
    desc: "Privilege escalation vulnerability",
  },
  {
    slug: "wordfence",
    name: "Wordfence",
    cve: "CVE-2020-28032",
    severity: "High",
    desc: "Authentication bypass in older versions",
  },
  {
    slug: "akismet",
    name: "Akismet",
    cve: "CVE-2015-9357",
    severity: "Medium",
    desc: "XSS vulnerability in older versions",
  },
  {
    slug: "jetpack",
    name: "Jetpack",
    cve: "CVE-2022-2637",
    severity: "Medium",
    desc: "Information disclosure vulnerability",
  },
  {
    slug: "wp-super-cache",
    name: "WP Super Cache",
    cve: "CVE-2021-24209",
    severity: "High",
    desc: "RCE vulnerability in versions below 1.7.3",
  },
  {
    slug: "nextgen-gallery",
    name: "NextGEN Gallery",
    cve: "CVE-2020-35942",
    severity: "Critical",
    desc: "SQL injection and XSS vulnerabilities",
  },
  {
    slug: "duplicator",
    name: "Duplicator",
    cve: "CVE-2020-11738",
    severity: "Critical",
    desc: "Arbitrary file read vulnerability",
  },
  {
    slug: "ninja-forms",
    name: "Ninja Forms",
    cve: "CVE-2021-34647",
    severity: "High",
    desc: "Authentication bypass",
  },
  {
    slug: "wp-file-manager",
    name: "WP File Manager",
    cve: "CVE-2020-25213",
    severity: "Critical",
    desc: "Unauthenticated arbitrary file upload — actively exploited",
  },
  {
    slug: "easy-wp-smtp",
    name: "Easy WP SMTP",
    cve: "CVE-2020-35234",
    severity: "Critical",
    desc: "Settings reset and admin account creation",
  },
  {
    slug: "ultimate-addons-for-gutenberg",
    name: "Ultimate Addons for Gutenberg",
    cve: "CVE-2020-11515",
    severity: "Critical",
    desc: "Authentication bypass",
  },
];

async function checkWordPressVersion(baseUrl) {
  const findings = [];
  let wpVersion = null;

  const sources = [
    `${baseUrl}/readme.html`,
    `${baseUrl}/wp-includes/version.php`,
    `${baseUrl}/feed/`,
    `${baseUrl}/`,
  ];

  for (const source of sources) {
    try {
      const res = await axiosInstance.get(source);
      const body = typeof res.data === "string" ? res.data : "";

      const versionPatterns = [
        /WordPress (\d+\.\d+\.?\d*)/i,
        /generator.*WordPress (\d+\.\d+\.?\d*)/i,
        /\?ver=(\d+\.\d+\.?\d*)/,
        /Version (\d+\.\d+\.?\d*)/i,
      ];

      for (const pattern of versionPatterns) {
        const match = body.match(pattern);
        if (match) {
          wpVersion = match[1];
          break;
        }
      }

      if (wpVersion) break;
    } catch (e) {}
  }

  if (wpVersion) {
    const majorVersion = parseFloat(wpVersion);
    if (majorVersion < 6.0) {
      findings.push({
        type: "Outdated WordPress Version",
        severity: "High",
        owasp: "A06:2021 - Vulnerable and Outdated Components",
        detail: `WordPress version ${wpVersion} detected. This version may contain known security vulnerabilities. Current stable version is 6.x.`,
        evidence: `WordPress ${wpVersion} found in page source`,
        remediation:
          "Update WordPress to the latest version immediately. Enable automatic updates in wp-admin → Dashboard → Updates.",
      });
    } else {
      findings.push({
        type: "WordPress Version Detected",
        severity: "Low",
        owasp: "A05:2021 - Security Misconfiguration",
        detail: `WordPress version ${wpVersion} detected. Version information should be hidden to prevent targeted attacks.`,
        evidence: `WordPress ${wpVersion} found in page source`,
        remediation:
          'Hide WordPress version by removing readme.html and adding remove_action("wp_head", "wp_generator") to functions.php.',
      });
    }
  }

  return { findings, wpVersion };
}

async function checkReadme(baseUrl) {
  const findings = [];
  try {
    const res = await axiosInstance.get(`${baseUrl}/readme.html`);
    if (
      res.status === 200 &&
      res.data.toString().toLowerCase().includes("wordpress")
    ) {
      findings.push({
        type: "WordPress Readme Exposed",
        severity: "Medium",
        owasp: "A05:2021 - Security Misconfiguration",
        detail:
          "readme.html is publicly accessible and reveals WordPress version information. Attackers use this to find matching exploits.",
        evidence: `GET ${baseUrl}/readme.html returned HTTP 200`,
        remediation:
          'Delete or restrict access to readme.html. Add "deny from all" in .htaccess for this file.',
      });
    }
  } catch (e) {}
  return findings;
}

async function checkXMLRPC(baseUrl) {
  const findings = [];
  try {
    const res = await axiosInstance.get(`${baseUrl}/xmlrpc.php`);
    if (res.status === 200 || res.status === 405) {
      const body = typeof res.data === "string" ? res.data : "";
      if (body.includes("xmlrpc") || res.status === 405) {
        findings.push({
          type: "XML-RPC Enabled",
          severity: "High",
          owasp: "A05:2021 - Security Misconfiguration",
          detail:
            "XML-RPC is enabled. Attackers use XML-RPC for brute force amplification attacks (one request tests hundreds of passwords), DDoS amplification, and remote code execution if combined with other vulnerabilities.",
          evidence: `GET ${baseUrl}/xmlrpc.php returned HTTP ${res.status}`,
          remediation:
            "Disable XML-RPC by adding \"add_filter('xmlrpc_enabled', '__return_false');\" to functions.php or use a security plugin.",
        });
      }
    }
  } catch (e) {}
  return findings;
}

async function checkUserEnumeration(baseUrl) {
  const findings = [];

  const enumUrls = [`${baseUrl}/?author=1`, `${baseUrl}/wp-json/wp/v2/users`];

  for (const url of enumUrls) {
    try {
      const res = await axiosInstance.get(url);
      const body =
        typeof res.data === "string" ? res.data : JSON.stringify(res.data);

      if (res.status === 200) {
        const hasUserData =
          body.includes('"slug"') ||
          body.includes('"name"') ||
          body.includes("author") ||
          (Array.isArray(res.data) && res.data.length > 0 && res.data[0].slug);

        if (hasUserData) {
          let users = [];
          if (Array.isArray(res.data)) {
            users = res.data
              .slice(0, 3)
              .map((u) => u.slug || u.name || "unknown");
          }

          findings.push({
            type: "User Enumeration Possible",
            severity: "Medium",
            owasp: "A01:2021 - Broken Access Control",
            detail: `WordPress usernames can be enumerated via the REST API or author archives. ${users.length > 0 ? `Found users: ${users.join(", ")}` : ""} Attackers use this to target specific accounts for brute force attacks.`,
            evidence: `GET ${url} returned user data with HTTP 200`,
            remediation:
              "Disable user enumeration by adding code to functions.php to redirect author queries. Disable the users REST endpoint or require authentication.",
          });
          break;
        }
      }
    } catch (e) {}
  }

  return findings;
}

async function checkWPJSON(baseUrl) {
  const findings = [];
  try {
    const res = await axiosInstance.get(`${baseUrl}/wp-json/wp/v2/users`);
    if (res.status === 200 && Array.isArray(res.data) && res.data.length > 0) {
      const users = res.data.slice(0, 5).map((u) => ({
        id: u.id,
        name: u.name,
        slug: u.slug,
        link: u.link,
      }));

      findings.push({
        type: "WP REST API Exposes User Data",
        severity: "High",
        owasp: "A01:2021 - Broken Access Control",
        detail: `WordPress REST API exposes ${res.data.length} user account(s) without authentication. User IDs, names and slugs are publicly visible.`,
        evidence: `wp-json/wp/v2/users returned ${res.data.length} users: ${users.map((u) => u.slug).join(", ")}`,
        remediation:
          'Restrict the users REST endpoint. Add authentication requirement or disable it: add_filter("rest_endpoints", function($endpoints){ unset($endpoints["/wp/v2/users"]); return $endpoints; });',
      });
    }
  } catch (e) {}
  return findings;
}

async function checkDebugMode(baseUrl) {
  const findings = [];
  try {
    const res = await axiosInstance.get(baseUrl);
    const body = typeof res.data === "string" ? res.data : "";

    if (
      body.includes("WP_DEBUG") ||
      body.includes("PHP Notice") ||
      body.includes("PHP Warning") ||
      body.includes("PHP Fatal error") ||
      body.includes("wp-content/debug.log")
    ) {
      findings.push({
        type: "WordPress Debug Mode Enabled",
        severity: "High",
        owasp: "A05:2021 - Security Misconfiguration",
        detail:
          "WordPress debug mode is enabled in production. This exposes PHP errors, file paths, database queries and potentially sensitive configuration data to all visitors.",
        evidence: "PHP errors or debug information found in page source",
        remediation:
          'Set WP_DEBUG to false in wp-config.php: define("WP_DEBUG", false). Never enable debug mode on production servers.',
      });
    }
  } catch (e) {}
  return findings;
}

async function checkUploadDirectoryListing(baseUrl) {
  const findings = [];
  try {
    const uploadUrls = [
      `${baseUrl}/wp-content/uploads/`,
      `${baseUrl}/wp-content/`,
    ];

    for (const url of uploadUrls) {
      const res = await axiosInstance.get(url);
      const body = typeof res.data === "string" ? res.data : "";

      if (
        res.status === 200 &&
        (body.includes("Index of") ||
          body.includes("Parent Directory") ||
          body.toLowerCase().includes("directory listing"))
      ) {
        findings.push({
          type: "WordPress Upload Directory Listing Enabled",
          severity: "Medium",
          owasp: "A05:2021 - Security Misconfiguration",
          detail:
            "Directory listing is enabled for wp-content/uploads. Attackers can browse all uploaded files including potentially sensitive documents.",
          evidence: `GET ${url} returned directory listing`,
          remediation:
            'Add "Options -Indexes" to .htaccess in wp-content/uploads/ to disable directory listing.',
        });
        break;
      }
    }
  } catch (e) {}
  return findings;
}

async function checkLoginPage(baseUrl) {
  const findings = [];
  try {
    const res = await axiosInstance.get(`${baseUrl}/wp-login.php`);
    if (res.status === 200) {
      findings.push({
        type: "WordPress Login Page Exposed",
        severity: "Low",
        owasp: "A07:2021 - Identification and Authentication Failures",
        detail:
          "The default WordPress login page (wp-login.php) is publicly accessible. This is a common target for brute force and credential stuffing attacks.",
        evidence: `GET ${baseUrl}/wp-login.php returned HTTP 200`,
        remediation:
          "Change the login URL using a plugin like WPS Hide Login. Implement 2FA. Add IP-based rate limiting to wp-login.php.",
      });

      // Check for brute force protection
      const loginAttempts = [];
      for (let i = 0; i < 5; i++) {
        try {
          const loginRes = await axiosInstance.post(
            `${baseUrl}/wp-login.php`,
            {
              log: "admin",
              pwd: `wrongpassword${i}`,
              "wp-submit": "Log In",
              redirect_to: "/wp-admin/",
              testcookie: "1",
            },
            {
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
            },
          );
          loginAttempts.push(loginRes.status);
          if (loginRes.status === 429) break;
        } catch (e) {}
      }

      if (!loginAttempts.includes(429) && !loginAttempts.includes(403)) {
        findings.push({
          type: "No Login Brute Force Protection",
          severity: "High",
          owasp: "A07:2021 - Identification and Authentication Failures",
          detail:
            "WordPress login page has no brute force protection. Attackers can make unlimited password attempts without being blocked.",
          evidence:
            "5 failed login attempts returned no 429 or lockout response",
          remediation:
            "Install Wordfence or Limit Login Attempts Reloaded plugin. Implement account lockout after 5 failed attempts. Enable 2FA for admin accounts.",
        });
      }
    }
  } catch (e) {}
  return findings;
}

async function enumeratePlugins(baseUrl, html) {
  const plugins = [];
  const vulnerableFound = [];

  const pluginPattern = /wp-content\/plugins\/([a-z0-9-_]+)\//gi;
  const matches = [...html.matchAll(pluginPattern)];
  const uniquePlugins = [...new Set(matches.map((m) => m[1]))];

  for (const slug of uniquePlugins.slice(0, 20)) {
    const knownVuln = VULNERABLE_PLUGINS.find((p) => p.slug === slug);
    const plugin = {
      slug,
      name: slug.replace(/-/g, " ").replace(/\b\w/g, (l) => l.toUpperCase()),
      vulnerable: !!knownVuln,
    };

    if (knownVuln) {
      plugin.cve = knownVuln.cve;
      plugin.severity = knownVuln.severity;
      plugin.vulnDesc = knownVuln.desc;
      vulnerableFound.push(plugin);
    }

    plugins.push(plugin);
  }

  return { plugins, vulnerableFound };
}

async function checkAdminUsername(baseUrl) {
  const findings = [];
  try {
    const res = await axiosInstance.get(`${baseUrl}/?author=1`);
    const body = typeof res.data === "string" ? res.data : "";

    if (
      body.toLowerCase().includes("/author/admin") ||
      body.toLowerCase().includes("author/admin")
    ) {
      findings.push({
        type: "Default Admin Username Detected",
        severity: "High",
        owasp: "A07:2021 - Identification and Authentication Failures",
        detail:
          'The default "admin" username is still in use. Combined with brute force attacks, this makes account compromise significantly easier since attackers already know the username.',
        evidence: 'Author slug "admin" found in page source',
        remediation:
          'Create a new admin account with a unique username and delete the default "admin" account. Never use "admin" as a username.',
      });
    }
  } catch (e) {}
  return findings;
}

async function checkWPCron(baseUrl) {
  const findings = [];
  try {
    const res = await axiosInstance.get(`${baseUrl}/wp-cron.php`);
    if (res.status === 200) {
      findings.push({
        type: "WP-Cron Publicly Accessible",
        severity: "Low",
        owasp: "A05:2021 - Security Misconfiguration",
        detail:
          "wp-cron.php is publicly accessible. Attackers can trigger scheduled tasks or use it for DoS by making many simultaneous requests.",
        evidence: `GET ${baseUrl}/wp-cron.php returned HTTP 200`,
        remediation:
          'Disable wp-cron in wp-config.php: define("DISABLE_WP_CRON", true); and set up a real cron job on the server.',
      });
    }
  } catch (e) {}
  return findings;
}

async function checkInstallationFiles(baseUrl) {
  const findings = [];
  const files = [
    { path: "/wp-config.php.bak", name: "WordPress config backup exposed" },
    { path: "/wp-config-sample.php", name: "WordPress config sample exposed" },
    { path: "/.wp-config.php.swp", name: "WordPress config swap file exposed" },
    { path: "/wp-content/debug.log", name: "WordPress debug log exposed" },
    {
      path: "/wp-admin/install.php",
      name: "WordPress install script accessible",
    },
    {
      path: "/wp-admin/upgrade.php",
      name: "WordPress upgrade script accessible",
    },
  ];

  for (const file of files) {
    try {
      const res = await axiosInstance.get(`${baseUrl}${file.path}`);
      if (res.status === 200) {
        findings.push({
          type: file.name,
          severity: "Critical",
          owasp: "A05:2021 - Security Misconfiguration",
          detail: `${file.name} at ${baseUrl}${file.path} is publicly accessible. This may expose database credentials, secret keys and other sensitive configuration.`,
          evidence: `GET ${file.path} returned HTTP 200`,
          remediation: `Immediately delete or restrict access to ${file.path}. Move sensitive files outside the web root.`,
        });
      }
    } catch (e) {}
  }

  return findings;
}

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target URL is required." });

  let baseUrl = target.trim();
  if (!baseUrl.startsWith("http")) baseUrl = "http://" + baseUrl;
  baseUrl = baseUrl.replace(/\/$/, "");

  console.log("Starting WordPress scan on:", baseUrl);

  try {
    // First check if it's actually WordPress
    const mainPage = await axiosInstance.get(baseUrl);
    const html = typeof mainPage.data === "string" ? mainPage.data : "";
    const isWordPress =
      html.includes("wp-content") ||
      html.includes("wp-includes") ||
      html.includes("wordpress");

    if (!isWordPress) {
      return res.json({
        success: true,
        data: {
          target: baseUrl,
          isWordPress: false,
          message: "This does not appear to be a WordPress site.",
          findings: [],
          plugins: [],
          summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
        },
      });
    }

    // Run all checks in parallel
    const [
      versionResult,
      readmeF,
      xmlrpcF,
      userEnumF,
      wpJsonF,
      debugF,
      uploadF,
      loginF,
      adminF,
      cronF,
      installF,
      pluginResult,
    ] = await Promise.all([
      checkWordPressVersion(baseUrl),
      checkReadme(baseUrl),
      checkXMLRPC(baseUrl),
      checkUserEnumeration(baseUrl),
      checkWPJSON(baseUrl),
      checkDebugMode(baseUrl),
      checkUploadDirectoryListing(baseUrl),
      checkLoginPage(baseUrl),
      checkAdminUsername(baseUrl),
      checkWPCron(baseUrl),
      checkInstallationFiles(baseUrl),
      enumeratePlugins(baseUrl, html),
    ]);

    const allFindings = [
      ...versionResult.findings,
      ...readmeF,
      ...xmlrpcF,
      ...userEnumF,
      ...wpJsonF,
      ...debugF,
      ...uploadF,
      ...loginF,
      ...adminF,
      ...cronF,
      ...installF,
    ];

    // Add vulnerable plugin findings
    pluginResult.vulnerableFound.forEach((plugin) => {
      allFindings.push({
        type: `Vulnerable Plugin: ${plugin.name}`,
        severity: plugin.severity,
        owasp: "A06:2021 - Vulnerable and Outdated Components",
        detail: `${plugin.name} plugin detected with known vulnerability: ${plugin.vulnDesc}`,
        evidence: `Plugin "${plugin.slug}" found in page source. CVE: ${plugin.cve}`,
        remediation: `Update ${plugin.name} to the latest version immediately. Check the plugin's changelog for security patches.`,
      });
    });

    const summary = {
      critical: allFindings.filter((f) => f.severity === "Critical").length,
      high: allFindings.filter((f) => f.severity === "High").length,
      medium: allFindings.filter((f) => f.severity === "Medium").length,
      low: allFindings.filter((f) => f.severity === "Low").length,
      total: allFindings.length,
    };

    const riskScore = Math.min(
      100,
      summary.critical * 30 +
        summary.high * 15 +
        summary.medium * 8 +
        summary.low * 3,
    );

    const result = {
      target: baseUrl,
      isWordPress: true,
      wpVersion: versionResult.wpVersion,
      plugins: pluginResult.plugins,
      vulnerablePlugins: pluginResult.vulnerableFound,
      findings: allFindings,
      summary,
      riskScore,
      scannedAt: new Date().toISOString(),
    };

    const severity =
      summary.critical > 0
        ? "critical"
        : summary.high > 0
          ? "high"
          : summary.medium > 0
            ? "medium"
            : "low";

    scansDb
      .insert({
        type: "WordPress Scan",
        userId: req.user?.id,
        target: baseUrl,
        result,
        findings_count: summary.total,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: result });
  } catch (err) {
    console.error("WordPress scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
