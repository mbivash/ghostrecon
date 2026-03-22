const express = require("express");
const router = express.Router();
const axios = require("axios");
const { scansDb } = require("../database");

const axiosInstance = axios.create({
  timeout: 15000,
  validateStatus: () => true,
  headers: { "User-Agent": "GhostRecon OAuth Scanner" },
});

async function findOAuthEndpoints(baseUrl) {
  const endpoints = {};
  const discoveryUrls = [
    `${baseUrl}/.well-known/openid-configuration`,
    `${baseUrl}/.well-known/oauth-authorization-server`,
    `${baseUrl}/oauth/.well-known/openid-configuration`,
    `${baseUrl}/auth/.well-known/openid-configuration`,
  ];

  for (const url of discoveryUrls) {
    try {
      const res = await axiosInstance.get(url);
      if (res.status === 200 && res.data) {
        const config = res.data;
        endpoints.discoveryUrl = url;
        endpoints.authorizationEndpoint = config.authorization_endpoint;
        endpoints.tokenEndpoint = config.token_endpoint;
        endpoints.introspectionEndpoint = config.introspection_endpoint;
        endpoints.revocationEndpoint = config.revocation_endpoint;
        endpoints.userinfoEndpoint = config.userinfo_endpoint;
        endpoints.jwksUri = config.jwks_uri;
        endpoints.grantTypes = config.grant_types_supported;
        endpoints.responseTypes = config.response_types_supported;
        endpoints.scopes = config.scopes_supported;
        break;
      }
    } catch (e) {}
  }

  return endpoints;
}

async function testOpenRedirect(authEndpoint) {
  const findings = [];
  if (!authEndpoint) return findings;

  const maliciousRedirects = [
    "https://evil.com",
    "https://evil.com/callback",
    "//evil.com",
    "https://evil.com@legitimate.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
  ];

  for (const redirect of maliciousRedirects.slice(0, 3)) {
    try {
      const testUrl = new URL(authEndpoint);
      testUrl.searchParams.set("client_id", "test");
      testUrl.searchParams.set("redirect_uri", redirect);
      testUrl.searchParams.set("response_type", "code");
      testUrl.searchParams.set("state", "ghostrecon_test");

      const res = await axiosInstance.get(testUrl.href, { maxRedirects: 0 });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers["location"] || "";
        if (location.includes("evil.com") || location.includes("javascript:")) {
          findings.push({
            type: "OAuth Open Redirect",
            severity: "High",
            owasp: "A01:2021 - Broken Access Control",
            endpoint: authEndpoint,
            detail:
              "OAuth authorization endpoint allows redirect to external domains. Attackers can steal authorization codes and access tokens.",
            evidence: `redirect_uri=${redirect} was accepted → Location: ${location}`,
            remediation:
              "Validate redirect_uri against a strict whitelist of registered URIs. Reject any URI not pre-registered.",
          });
          break;
        }
      }
    } catch (e) {}
  }

  return findings;
}

async function testCSRFInOAuth(authEndpoint) {
  const findings = [];
  if (!authEndpoint) return findings;

  try {
    const testUrl = new URL(authEndpoint);
    testUrl.searchParams.set("client_id", "test");
    testUrl.searchParams.set("redirect_uri", "https://example.com/callback");
    testUrl.searchParams.set("response_type", "code");

    const res = await axiosInstance.get(testUrl.href, { maxRedirects: 0 });

    if (
      res.status === 200 ||
      (res.status >= 300 && !res.headers["location"]?.includes("state="))
    ) {
      findings.push({
        type: "OAuth Missing State Parameter",
        severity: "High",
        owasp: "A01:2021 - Broken Access Control",
        endpoint: authEndpoint,
        detail:
          "OAuth flow does not enforce the state parameter. This allows CSRF attacks where an attacker tricks a user into authorizing the attacker's account.",
        evidence: "Authorization request succeeded without state parameter",
        remediation:
          "Require and validate the state parameter in all OAuth flows. Use cryptographically random state values.",
      });
    }
  } catch (e) {}

  return findings;
}

async function testTokenLeakage(authEndpoint) {
  const findings = [];
  if (!authEndpoint) return findings;

  try {
    const testUrl = new URL(authEndpoint);
    testUrl.searchParams.set("client_id", "test");
    testUrl.searchParams.set("redirect_uri", "https://example.com/callback");
    testUrl.searchParams.set("response_type", "token");
    testUrl.searchParams.set("state", "test");

    const res = await axiosInstance.get(testUrl.href);
    const body = JSON.stringify(res.data);

    if (body.includes("access_token") || body.includes("id_token")) {
      findings.push({
        type: "OAuth Token in Response Body",
        severity: "High",
        owasp: "A02:2021 - Cryptographic Failures",
        endpoint: authEndpoint,
        detail:
          "OAuth server returns tokens in response body or URL fragment. Tokens can leak through browser history, logs, and referrer headers.",
        evidence: "access_token or id_token found in response",
        remediation:
          "Use authorization code flow instead of implicit flow. Never return tokens in URLs. Use PKCE for public clients.",
      });
    }
  } catch (e) {}

  return findings;
}

async function testJWTWeakness(tokenEndpoint) {
  const findings = [];
  if (!tokenEndpoint) return findings;

  try {
    const res = await axiosInstance.post(tokenEndpoint, {
      grant_type: "client_credentials",
      client_id: "test",
      client_secret: "test",
    });

    const body = typeof res.data === "object" ? res.data : {};
    const token = body.access_token || body.id_token;

    if (token) {
      const parts = token.split(".");
      if (parts.length === 3) {
        try {
          const header = JSON.parse(Buffer.from(parts[0], "base64").toString());
          if (header.alg === "none" || header.alg === "NONE") {
            findings.push({
              type: "JWT None Algorithm in OAuth Token",
              severity: "Critical",
              owasp: "A02:2021 - Cryptographic Failures",
              endpoint: tokenEndpoint,
              detail:
                'OAuth server issues JWT tokens with "none" algorithm. Attackers can forge tokens without a valid signature.',
              evidence: `JWT header alg: ${header.alg}`,
              remediation:
                "Use RS256 or ES256. Reject tokens with none algorithm.",
            });
          }
          if (header.alg === "HS256") {
            findings.push({
              type: "JWT Weak Algorithm in OAuth Token",
              severity: "Medium",
              owasp: "A02:2021 - Cryptographic Failures",
              endpoint: tokenEndpoint,
              detail:
                "OAuth server uses HS256 symmetric algorithm. If secret is weak, tokens can be brute-forced.",
              evidence: "JWT uses HS256",
              remediation: "Upgrade to RS256 or ES256 asymmetric algorithms.",
            });
          }
        } catch (e) {}
      }
    }
  } catch (e) {}

  return findings;
}

async function testPKCE(authEndpoint) {
  const findings = [];
  if (!authEndpoint) return findings;

  try {
    const testUrl = new URL(authEndpoint);
    testUrl.searchParams.set("client_id", "test");
    testUrl.searchParams.set("redirect_uri", "https://example.com/callback");
    testUrl.searchParams.set("response_type", "code");
    testUrl.searchParams.set("state", "test");

    const res = await axiosInstance.get(testUrl.href);

    if (
      res.status !== 400 &&
      !JSON.stringify(res.data).includes("code_challenge")
    ) {
      findings.push({
        type: "OAuth PKCE Not Required",
        severity: "Medium",
        owasp: "A07:2021 - Identification and Authentication Failures",
        endpoint: authEndpoint,
        detail:
          "OAuth server does not require PKCE (Proof Key for Code Exchange). Public clients are vulnerable to authorization code interception attacks.",
        evidence: "Authorization request without code_challenge was accepted",
        remediation:
          "Require PKCE for all public clients. Use S256 challenge method. Reject requests without code_challenge.",
      });
    }
  } catch (e) {}

  return findings;
}

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target URL is required." });

  let baseUrl = target.trim();
  if (!baseUrl.startsWith("http")) baseUrl = "https://" + baseUrl;

  try {
    const results = {
      target: baseUrl,
      findings: [],
      endpoints: {},
      scannedAt: new Date().toISOString(),
    };

    console.log("Discovering OAuth endpoints...");
    const endpoints = await findOAuthEndpoints(baseUrl);
    results.endpoints = endpoints;

    if (!endpoints.discoveryUrl) {
      results.findings.push({
        type: "No OAuth Discovery Document Found",
        severity: "Info",
        detail: `No OAuth/OIDC discovery document found for ${baseUrl}.`,
        evidence: "Checked /.well-known/openid-configuration and similar paths",
        remediation:
          "If you use OAuth, ensure your discovery document is properly configured.",
      });
    } else {
      results.findings.push({
        type: "OAuth Discovery Document Found",
        severity: "Info",
        endpoint: endpoints.discoveryUrl,
        detail: `OAuth/OIDC configuration discovered. Found authorization endpoint, token endpoint, and ${endpoints.scopes?.length || 0} supported scopes.`,
        evidence: `Discovery at ${endpoints.discoveryUrl}`,
        remediation:
          "Review all exposed endpoints and ensure proper security controls.",
      });
    }

    const [
      redirectFindings,
      csrfFindings,
      tokenLeakFindings,
      jwtFindings,
      pkceFindings,
    ] = await Promise.all([
      testOpenRedirect(endpoints.authorizationEndpoint),
      testCSRFInOAuth(endpoints.authorizationEndpoint),
      testTokenLeakage(endpoints.authorizationEndpoint),
      testJWTWeakness(endpoints.tokenEndpoint),
      testPKCE(endpoints.authorizationEndpoint),
    ]);

    results.findings.push(
      ...redirectFindings,
      ...csrfFindings,
      ...tokenLeakFindings,
      ...jwtFindings,
      ...pkceFindings,
    );

    results.summary = {
      endpointsFound: Object.keys(endpoints).length,
      critical: results.findings.filter((f) => f.severity === "Critical")
        .length,
      high: results.findings.filter((f) => f.severity === "High").length,
      medium: results.findings.filter((f) => f.severity === "Medium").length,
      low: results.findings.filter((f) => f.severity === "Low").length,
      total: results.findings.length,
    };

    const severity =
      results.summary.critical > 0
        ? "critical"
        : results.summary.high > 0
          ? "high"
          : results.summary.medium > 0
            ? "medium"
            : "info";

    scansDb
      .insert({
        type: "OAuth Security Scan",
        userId: req.user?.id,
        target: baseUrl,
        result: results,
        findings_count: results.summary.total,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: results });
  } catch (err) {
    console.error("OAuth scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
