// ═══════════════════════════════════════════════════════
// GhostRecon — Two-Account IDOR Tester
// Logs in as two different users and checks if
// Account A can access Account B's data
// ═══════════════════════════════════════════════════════

const axios = require("axios");
const cheerio = require("cheerio");

// ── Session creator — logs in and returns cookie session ──
async function createSession(loginUrl, username, password) {
  const instance = axios.create({
    timeout: 15000,
    validateStatus: () => true,
    maxRedirects: 5,
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; GhostRecon Security Scanner)",
      "Content-Type": "application/x-www-form-urlencoded",
    },
  });

  // Fetch login page
  const loginPage = await instance.get(loginUrl);
  const $ = cheerio.load(loginPage.data);

  // Find login form
  let formAction = loginUrl;
  let csrfToken = null;

  $("form").each((i, form) => {
    const inputs = [];
    $(form)
      .find("input")
      .each((j, input) => {
        inputs.push({
          name: $(input).attr("name"),
          type: $(input).attr("type") || "text",
          value: $(input).attr("value") || "",
        });
      });
    const hasPassword = inputs.some(
      (inp) =>
        inp.type === "password" ||
        (inp.name || "").toLowerCase().includes("pass"),
    );
    if (hasPassword) {
      formAction = new URL($(form).attr("action") || loginUrl, loginUrl).href;
      // Grab CSRF token if present
      const csrfInput = inputs.find(
        (inp) =>
          (inp.name || "").toLowerCase().includes("csrf") ||
          (inp.name || "").toLowerCase().includes("token") ||
          (inp.name || "").toLowerCase().includes("nonce"),
      );
      if (csrfInput) csrfToken = csrfInput.value;
    }
  });

  // Build form data
  const formData = new URLSearchParams();
  $("form input").each((i, input) => {
    const name = $(input).attr("name");
    const type = $(input).attr("type") || "text";
    const value = $(input).attr("value") || "";
    if (!name) return;
    const nameLower = name.toLowerCase();
    if (
      type === "password" ||
      nameLower.includes("pass") ||
      nameLower.includes("pwd")
    ) {
      formData.append(name, password);
    } else if (
      nameLower.includes("user") ||
      nameLower.includes("email") ||
      nameLower.includes("login")
    ) {
      formData.append(name, username);
    } else if (value) {
      formData.append(name, value);
    }
  });

  // Submit login
  const loginResponse = await instance.post(formAction, formData.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    maxRedirects: 5,
  });

  const cookies = loginResponse.headers["set-cookie"] || [];
  if (cookies.length === 0)
    throw new Error(
      `Login failed for ${username} — no session cookies returned`,
    );

  const cookieHeader = cookies.map((c) => c.split(";")[0]).join("; ");

  // Create authenticated axios instance
  const authedInstance = axios.create({
    timeout: 15000,
    validateStatus: () => true,
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; GhostRecon Security Scanner)",
      Cookie: cookieHeader,
    },
    maxRedirects: 3,
  });

  return { instance: authedInstance, cookies: cookieHeader, username };
}

// ── API Session creator — for token-based auth (JWT/Bearer) ──
async function createAPISession(loginUrl, username, password) {
  const instance = axios.create({
    timeout: 15000,
    validateStatus: () => true,
  });

  // Try common API login endpoints
  const loginEndpoints = [
    { url: loginUrl, method: "post", data: { email: username, password } },
    { url: loginUrl, method: "post", data: { username, password } },
    {
      url: loginUrl.replace("/login", "/auth"),
      method: "post",
      data: { email: username, password },
    },
    {
      url: loginUrl.replace("/login", "/signin"),
      method: "post",
      data: { email: username, password },
    },
  ];

  for (const endpoint of loginEndpoints) {
    try {
      const response = await instance.post(endpoint.url, endpoint.data, {
        headers: { "Content-Type": "application/json" },
      });

      const body = response.data;

      // Look for token in response
      const token =
        body?.token ||
        body?.access_token ||
        body?.accessToken ||
        body?.data?.token ||
        body?.data?.access_token ||
        body?.result?.token ||
        body?.jwt;

      if (token) {
        const authedInstance = axios.create({
          timeout: 15000,
          validateStatus: () => true,
          headers: {
            "User-Agent":
              "Mozilla/5.0 (compatible; GhostRecon Security Scanner)",
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });
        return { instance: authedInstance, token, username };
      }
    } catch (e) {}
  }

  throw new Error(`API login failed for ${username} — no token in response`);
}

// ── URL ID extractor ──────────────────────────────────
function extractIDsFromURL(url) {
  const ids = [];
  const patterns = [
    {
      regex:
        /[?&](id|user_id|account_id|order_id|profile_id|invoice_id|doc_id|file_id|record_id|item_id)=(\d+)/gi,
      type: "query",
    },
    {
      regex:
        /\/(user|account|order|invoice|profile|document|file|record|item|transaction|trade|portfolio|wallet)\/(\d+)/gi,
      type: "path",
    },
    { regex: /[?&](\w+_id)=(\d+)/gi, type: "query" },
  ];

  for (const { regex, type } of patterns) {
    for (const match of [...url.matchAll(regex)]) {
      ids.push({ param: match[1], value: match[2], type, fullMatch: match[0] });
    }
  }
  return ids;
}

// ── Core IDOR test ────────────────────────────────────
async function testIDOROnEndpoint(url, sessionA, sessionB) {
  const findings = [];
  const ids = extractIDsFromURL(url);
  if (ids.length === 0) return findings;

  // Get original response from Session A (owner)
  let originalResponse;
  try {
    originalResponse = await sessionA.instance.get(url);
  } catch (e) {
    return findings;
  }

  if (originalResponse.status !== 200) return findings;

  const originalBody =
    typeof originalResponse.data === "string"
      ? originalResponse.data
      : JSON.stringify(originalResponse.data);

  // Now try with Session B (attacker) — same URL
  try {
    const attackResponse = await sessionB.instance.get(url);

    if (attackResponse.status === 200) {
      const attackBody =
        typeof attackResponse.data === "string"
          ? attackResponse.data
          : JSON.stringify(attackResponse.data);

      // Check if B got meaningful data that looks like A's data
      const isUnauthorized =
        attackBody.toLowerCase().includes("unauthorized") ||
        attackBody.toLowerCase().includes("forbidden") ||
        attackBody.toLowerCase().includes("access denied") ||
        attackBody.toLowerCase().includes("not allowed") ||
        attackBody.toLowerCase().includes("permission");

      if (!isUnauthorized && attackBody.length > 100) {
        // Check if response contains user-specific data from A
        const containsUserData =
          originalBody.length > 50 &&
          attackBody.length > 50 &&
          attackBody !== "<html>" &&
          !attackBody.includes("login") &&
          !attackBody.includes("sign in");

        if (containsUserData) {
          findings.push({
            type: "IDOR — Cross-Account Data Access",
            severity: "High",
            confidence: "Probable",
            owasp: "A01:2021 - Broken Access Control",
            endpoint: url,
            method: "GET",
            detail: `Account B (${sessionB.username}) can access data belonging to Account A (${sessionA.username}). This endpoint does not properly verify ownership before returning data.`,
            evidence: `GET ${url} — Account B received HTTP 200 with ${attackBody.length} bytes of data`,
            remediation:
              "Implement object-level authorization. Always verify the requesting user owns the resource before returning it.",
            accountA: sessionA.username,
            accountB: sessionB.username,
          });
        }
      }
    }
  } catch (e) {}

  // Also test with mutated IDs (try nearby IDs)
  for (const id of ids) {
    const testIds = [
      parseInt(id.value) - 1,
      parseInt(id.value) + 1,
      1,
      2,
      3,
      100,
      999,
    ].filter((v) => v > 0 && v.toString() !== id.value);

    for (const testId of testIds.slice(0, 3)) {
      try {
        const mutatedUrl = url.replace(
          id.fullMatch,
          id.fullMatch.replace(id.value, testId.toString()),
        );
        const response = await sessionB.instance.get(mutatedUrl);

        if (response.status === 200) {
          const body =
            typeof response.data === "string"
              ? response.data
              : JSON.stringify(response.data);

          const isBlocked =
            body.toLowerCase().includes("unauthorized") ||
            body.toLowerCase().includes("not found") ||
            body.toLowerCase().includes("forbidden") ||
            body.length < 50;

          if (!isBlocked) {
            findings.push({
              type: "IDOR — ID Enumeration",
              severity: "High",
              confidence: "Probable",
              owasp: "A01:2021 - Broken Access Control",
              endpoint: mutatedUrl,
              method: "GET",
              originalId: id.value,
              testedId: testId.toString(),
              detail: `Changing ${id.param} from ${id.value} to ${testId} returns data. Attacker can enumerate and access other users' resources.`,
              evidence: `GET ${mutatedUrl} → HTTP 200 (${body.length} bytes)`,
              remediation:
                "Validate that the authenticated user owns the requested resource ID before returning data.",
            });
            break;
          }
        }
      } catch (e) {}
    }
  }

  return findings;
}

// ── API endpoint discovery ────────────────────────────
async function discoverAPIEndpoints(baseUrl, session) {
  const endpoints = [];
  const commonAPIPaths = [
    "/api/user",
    "/api/me",
    "/api/profile",
    "/api/account",
    "/api/orders",
    "/api/transactions",
    "/api/portfolio",
    "/api/wallet",
    "/api/balance",
    "/api/history",
    "/api/v1/user",
    "/api/v1/account",
    "/api/v1/orders",
    "/api/v2/user",
    "/api/v2/account",
    "/api/v2/orders",
    "/user/profile",
    "/account/details",
    "/dashboard/data",
  ];

  for (const path of commonAPIPaths) {
    try {
      const url = new URL(path, baseUrl).href;
      const response = await session.instance.get(url);
      if (
        response.status === 200 &&
        response.data &&
        typeof response.data === "object"
      ) {
        endpoints.push({
          url,
          status: response.status,
          dataSize: JSON.stringify(response.data).length,
        });
      }
    } catch (e) {}
  }

  return endpoints;
}

// ── Main IDOR scan ────────────────────────────────────
async function runIDORScan(config) {
  const {
    targetUrl,
    loginUrl,
    account1: { username: user1, password: pass1 },
    account2: { username: user2, password: pass2 },
    authType = "cookie", // "cookie" or "api"
    customEndpoints = [],
  } = config;

  const results = {
    target: targetUrl,
    findings: [],
    testedEndpoints: [],
    sessionA: null,
    sessionB: null,
    apiEndpoints: [],
    startTime: new Date().toISOString(),
  };

  // Create sessions for both accounts
  console.log(`Creating session for Account A: ${user1}`);
  let sessionA, sessionB;

  try {
    if (authType === "api") {
      sessionA = await createAPISession(loginUrl || targetUrl, user1, pass1);
    } else {
      sessionA = await createSession(loginUrl || targetUrl, user1, pass1);
    }
    results.sessionA = { username: user1, authenticated: true };
    console.log(`Session A created for ${user1}`);
  } catch (e) {
    results.sessionA = {
      username: user1,
      authenticated: false,
      error: e.message,
    };
    throw new Error(`Account A login failed: ${e.message}`);
  }

  try {
    if (authType === "api") {
      sessionB = await createAPISession(loginUrl || targetUrl, user2, pass2);
    } else {
      sessionB = await createSession(loginUrl || targetUrl, user2, pass2);
    }
    results.sessionB = { username: user2, authenticated: true };
    console.log(`Session B created for ${user2}`);
  } catch (e) {
    results.sessionB = {
      username: user2,
      authenticated: false,
      error: e.message,
    };
    throw new Error(`Account B login failed: ${e.message}`);
  }

  // Discover API endpoints from Account A's session
  console.log("Discovering API endpoints...");
  const discoveredEndpoints = await discoverAPIEndpoints(targetUrl, sessionA);
  results.apiEndpoints = discoveredEndpoints;

  // Build list of URLs to test
  const urlsToTest = [
    ...customEndpoints,
    ...discoveredEndpoints.map((e) => e.url),
  ];

  // Crawl authenticated pages from Account A to find more URLs with IDs
  try {
    const baseResponse = await sessionA.instance.get(targetUrl);
    if (baseResponse.status === 200 && typeof baseResponse.data === "string") {
      const $ = cheerio.load(baseResponse.data);
      $("a[href]").each((i, el) => {
        const href = $(el).attr("href");
        if (!href) return;
        try {
          const absolute = new URL(href, targetUrl).href;
          if (absolute.startsWith(targetUrl)) {
            const ids = extractIDsFromURL(absolute);
            if (ids.length > 0) urlsToTest.push(absolute);
          }
        } catch (e) {}
      });
    }
  } catch (e) {}

  console.log(`Testing ${urlsToTest.length} endpoints for IDOR...`);

  // Test each endpoint
  for (const url of urlsToTest.slice(0, 30)) {
    results.testedEndpoints.push(url);
    const findings = await testIDOROnEndpoint(url, sessionA, sessionB);
    results.findings.push(...findings);
    if (results.findings.length > 0) {
      console.log(`IDOR found at: ${url}`);
    }
  }

  results.endTime = new Date().toISOString();
  results.summary = {
    total: results.findings.length,
    high: results.findings.filter((f) => f.severity === "High").length,
    critical: results.findings.filter((f) => f.severity === "Critical").length,
    testedEndpoints: results.testedEndpoints.length,
    apiEndpointsFound: results.apiEndpoints.length,
  };

  return results;
}

module.exports = { runIDORScan, createSession, createAPISession };
