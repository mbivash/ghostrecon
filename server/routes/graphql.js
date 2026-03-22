const express = require("express");
const router = express.Router();
const axios = require("axios");
const { scansDb } = require("../database");

const axiosInstance = axios.create({
  timeout: 15000,
  validateStatus: () => true,
  headers: {
    "Content-Type": "application/json",
    "User-Agent": "GhostRecon GraphQL Scanner",
  },
});

const INTROSPECTION_QUERY = `{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind } }
        type { name kind }
      }
    }
  }
}`;

async function findGraphQLEndpoint(baseUrl) {
  const paths = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/query",
    "/gql",
    "/graph",
    "/graphql/v1",
    "/graphql/v2",
    "/playground",
  ];

  for (const path of paths) {
    try {
      const url = `${baseUrl}${path}`;
      const res = await axiosInstance.post(url, { query: "{ __typename }" });
      if (
        res.status === 200 &&
        res.data &&
        (res.data.data || res.data.errors)
      ) {
        return url;
      }
    } catch (e) {}
  }
  return null;
}

async function testIntrospection(endpoint) {
  const findings = [];
  try {
    const res = await axiosInstance.post(endpoint, {
      query: INTROSPECTION_QUERY,
    });
    if (res.status === 200 && res.data?.data?.__schema) {
      const schema = res.data.data.__schema;
      const types = schema.types?.filter((t) => !t.name.startsWith("__")) || [];
      const queries =
        types.find((t) => t.name === schema.queryType?.name)?.fields || [];
      const mutations =
        types.find((t) => t.name === schema.mutationType?.name)?.fields || [];

      findings.push({
        type: "GraphQL Introspection Enabled",
        severity: "Medium",
        owasp: "A05:2021 - Security Misconfiguration",
        endpoint,
        detail: `GraphQL introspection is enabled in production. Attackers can map your entire API schema including ${queries.length} queries and ${mutations.length} mutations.`,
        evidence: `Introspection returned ${types.length} types, ${queries.length} queries, ${mutations.length} mutations`,
        remediation:
          "Disable introspection in production. Use query depth limiting. Implement query whitelisting.",
        schema: {
          types: types.length,
          queries: queries.map((q) => q.name),
          mutations: mutations.map((m) => m.name),
        },
      });

      // Check for sensitive field names
      const sensitiveFields = [
        "password",
        "token",
        "secret",
        "key",
        "credit_card",
        "ssn",
        "private",
        "internal",
      ];
      const allFields = types
        .flatMap((t) => t.fields || [])
        .map((f) => f.name.toLowerCase());

      const foundSensitive = sensitiveFields.filter((s) =>
        allFields.some((f) => f.includes(s)),
      );
      if (foundSensitive.length > 0) {
        findings.push({
          type: "Sensitive Fields in GraphQL Schema",
          severity: "High",
          owasp: "A02:2021 - Cryptographic Failures",
          endpoint,
          detail: `GraphQL schema exposes potentially sensitive fields: ${foundSensitive.join(", ")}. These fields may return sensitive data.`,
          evidence: `Sensitive field names found: ${foundSensitive.join(", ")}`,
          remediation:
            "Review all sensitive fields. Ensure they require authentication. Consider removing from schema if not needed.",
        });
      }

      return { findings, schema: { types, queries, mutations } };
    }
  } catch (e) {}
  return { findings, schema: null };
}

async function testBatchingAttack(endpoint) {
  const findings = [];
  try {
    // Test array batching
    const batchQuery = Array(10).fill({ query: "{ __typename }" });
    const res = await axiosInstance.post(endpoint, batchQuery);

    if (res.status === 200 && Array.isArray(res.data)) {
      findings.push({
        type: "GraphQL Batching Attack Possible",
        severity: "High",
        owasp: "A04:2021 - Insecure Design",
        endpoint,
        detail:
          "GraphQL accepts batched queries. Attackers can send hundreds of queries in a single request, bypassing rate limits and brute forcing credentials.",
        evidence: `Array of 10 queries returned ${res.data.length} results in one request`,
        remediation:
          "Disable query batching or limit batch size to 5. Implement rate limiting per query, not per request.",
      });
    }
  } catch (e) {}
  return findings;
}

async function testDepthLimit(endpoint) {
  const findings = [];
  const deepQuery = `{ a { b { c { d { e { f { g { h { __typename } } } } } } } } }`;
  try {
    const res = await axiosInstance.post(endpoint, { query: deepQuery });
    if (res.status === 200 && res.data && !res.data.errors) {
      findings.push({
        type: "GraphQL No Query Depth Limit",
        severity: "High",
        owasp: "A04:2021 - Insecure Design",
        endpoint,
        detail:
          "GraphQL has no query depth limit. Attackers can send deeply nested queries causing exponential database load and DoS.",
        evidence: "8-level deep nested query executed without error",
        remediation:
          "Implement query depth limiting (max 5-7 levels). Use graphql-depth-limit package. Implement query complexity analysis.",
      });
    }
  } catch (e) {}
  return findings;
}

async function testFieldSuggestions(endpoint) {
  const findings = [];
  try {
    const res = await axiosInstance.post(endpoint, { query: "{ usr { id } }" });
    const body = JSON.stringify(res.data);
    if (
      body.includes("Did you mean") ||
      body.includes("didYouMean") ||
      body.includes("suggestions")
    ) {
      findings.push({
        type: "GraphQL Field Suggestions Enabled",
        severity: "Low",
        owasp: "A05:2021 - Security Misconfiguration",
        endpoint,
        detail:
          "GraphQL returns field suggestions for typos. Attackers use this to enumerate schema fields without introspection.",
        evidence: 'Typo query returned "Did you mean" suggestion',
        remediation:
          "Disable field suggestions in production GraphQL configuration.",
      });
    }
  } catch (e) {}
  return findings;
}

async function testInjection(endpoint, schema) {
  const findings = [];
  if (!schema || !schema.queries) return findings;

  const sqliPayloads = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT null--",
  ];
  const xssPayloads = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
  ];

  for (const query of schema.queries.slice(0, 3)) {
    for (const payload of sqliPayloads.slice(0, 2)) {
      try {
        const testQuery = `{ ${query}(id: "${payload}") { id } }`;
        const res = await axiosInstance.post(endpoint, { query: testQuery });
        const body = JSON.stringify(res.data).toLowerCase();
        const sqlErrors = ["sql syntax", "mysql_", "pg::", "ora-", "sqlite"];
        if (sqlErrors.some((e) => body.includes(e))) {
          findings.push({
            type: "GraphQL SQL Injection",
            severity: "Critical",
            owasp: "A03:2021 - Injection",
            endpoint,
            detail: `SQL injection in GraphQL query "${query}". Full database access possible through the GraphQL layer.`,
            evidence: `SQL error triggered via GraphQL query: ${query}`,
            remediation:
              "Use parameterized queries in all GraphQL resolvers. Validate all input arguments.",
          });
          break;
        }
      } catch (e) {}
    }
  }

  return findings;
}

async function testCircularQuery(endpoint) {
  const findings = [];
  try {
    // Alias-based DoS
    const aliasQuery = Array(100)
      .fill(null)
      .map((_, i) => `q${i}: __typename`)
      .join("\n");
    const query = `{ ${aliasQuery} }`;
    const res = await axiosInstance.post(
      endpoint,
      { query },
      { timeout: 5000 },
    );

    if (res.status === 200) {
      findings.push({
        type: "GraphQL Alias DoS Possible",
        severity: "Medium",
        owasp: "A04:2021 - Insecure Design",
        endpoint,
        detail:
          "GraphQL allows 100+ aliases in a single query. This can be used for DoS attacks — a single request can cause massive server load.",
        evidence: "100-alias query executed successfully",
        remediation:
          "Implement query complexity analysis. Limit number of aliases per query. Use persisted queries.",
      });
    }
  } catch (e) {}
  return findings;
}

router.post("/scan", async (req, res) => {
  const { target, consent, graphqlUrl } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target URL is required." });

  let baseUrl = target.trim();
  if (!baseUrl.startsWith("http")) baseUrl = "http://" + baseUrl;

  try {
    const results = {
      target: baseUrl,
      endpointFound: false,
      graphqlEndpoint: null,
      findings: [],
      schema: null,
      scannedAt: new Date().toISOString(),
    };

    // Find GraphQL endpoint
    console.log("Finding GraphQL endpoint...");
    const endpoint = graphqlUrl || (await findGraphQLEndpoint(baseUrl));

    if (!endpoint) {
      results.findings.push({
        type: "No GraphQL Endpoint Found",
        severity: "Info",
        detail: `No GraphQL endpoint found at common paths for ${baseUrl}.`,
        evidence:
          "Checked /graphql, /graphiql, /api/graphql and 8 other common paths",
        remediation: "If you use GraphQL, provide the exact endpoint URL.",
      });
      return res.json({
        success: true,
        data: { ...results, summary: { total: 0 } },
      });
    }

    results.endpointFound = true;
    results.graphqlEndpoint = endpoint;
    console.log("GraphQL endpoint found:", endpoint);

    // Run all checks
    const [
      introResult,
      batchFindings,
      depthFindings,
      suggestionFindings,
      circularFindings,
    ] = await Promise.all([
      testIntrospection(endpoint),
      testBatchingAttack(endpoint),
      testDepthLimit(endpoint),
      testFieldSuggestions(endpoint),
      testCircularQuery(endpoint),
    ]);

    results.findings.push(
      ...introResult.findings,
      ...batchFindings,
      ...depthFindings,
      ...suggestionFindings,
      ...circularFindings,
    );
    results.schema = introResult.schema;

    // Test injection if we have schema
    if (introResult.schema) {
      const injectionFindings = await testInjection(
        endpoint,
        introResult.schema,
      );
      results.findings.push(...injectionFindings);
    }

    results.summary = {
      endpointFound: true,
      graphqlEndpoint: endpoint,
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
        type: "GraphQL Scan",
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
    console.error("GraphQL scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
