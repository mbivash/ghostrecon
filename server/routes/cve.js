const express = require("express");
const router = express.Router();
const https = require("https");

function fetchCVEs(keyword) {
  return new Promise((resolve) => {
    const query = encodeURIComponent(keyword);
    const options = {
      hostname: "services.nvd.nist.gov",
      path: `/rest/json/cves/2.0?keywordSearch=${query}&resultsPerPage=5`,
      method: "GET",
      headers: {
        "User-Agent": "GhostRecon Security Scanner",
      },
      timeout: 10000,
    };

    https
      .get(options, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            const cves = (parsed.vulnerabilities || []).map((v) => {
              const cve = v.cve;
              const metrics =
                cve.metrics?.cvssMetricV31?.[0] ||
                cve.metrics?.cvssMetricV30?.[0] ||
                cve.metrics?.cvssMetricV2?.[0];

              const score = metrics?.cvssData?.baseScore || 0;
              const severity =
                metrics?.cvssData?.baseSeverity ||
                (score >= 9
                  ? "CRITICAL"
                  : score >= 7
                    ? "HIGH"
                    : score >= 4
                      ? "MEDIUM"
                      : "LOW");

              const description =
                cve.descriptions?.find((d) => d.lang === "en")?.value ||
                "No description available";

              return {
                id: cve.id,
                score: parseFloat(score.toFixed(1)),
                severity,
                description:
                  description.length > 200
                    ? description.substring(0, 200) + "..."
                    : description,
                published: cve.published?.split("T")[0] || "Unknown",
                url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
              };
            });
            resolve(cves);
          } catch (e) {
            resolve([]);
          }
        });
      })
      .on("error", () => resolve([]))
      .on("timeout", () => resolve([]));
  });
}

router.get("/search", async (req, res) => {
  const { keyword } = req.query;

  if (!keyword) {
    return res.status(400).json({ error: "Keyword is required." });
  }

  try {
    const cves = await fetchCVEs(keyword);
    res.json({ success: true, cves, keyword });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/scan", async (req, res) => {
  const { services } = req.body;

  if (!services || services.length === 0) {
    return res.status(400).json({ error: "Services list is required." });
  }

  try {
    const results = {};

    for (const service of services.slice(0, 5)) {
      if (service && service !== "unknown") {
        console.log(`Fetching CVEs for: ${service}`);
        const cves = await fetchCVEs(service);
        if (cves.length > 0) {
          results[service] = cves;
        }
        // Small delay to respect rate limits
        await new Promise((r) => setTimeout(r, 500));
      }
    }

    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
