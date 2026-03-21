const express = require("express");
const router = express.Router();
const axios = require("axios");
const dns = require("dns").promises;
const { scansDb } = require("../database");

async function resolveToIP(target) {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipRegex.test(target)) return target;
  try {
    const addresses = await dns.resolve4(target);
    return addresses[0];
  } catch (e) {
    throw new Error(`Could not resolve domain: ${target}`);
  }
}

async function scanWithShodan(ip) {
  try {
    const res = await axios.get(`https://internetdb.shodan.io/${ip}`, {
      timeout: 15000,
    });
    return res.data;
  } catch (err) {
    if (err.response?.status === 404) {
      return { ip, ports: [], hostnames: [], tags: [], vulns: [], cpes: [] };
    }
    throw new Error("Shodan API failed: " + err.message);
  }
}

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent) {
    return res.status(403).json({
      error: "You must confirm you have permission to scan this target.",
    });
  }

  if (!target) {
    return res.status(400).json({ error: "Target is required." });
  }

  try {
    console.log("Resolving target:", target);
    const ip = await resolveToIP(target.trim());
    console.log("Resolved to IP:", ip);

    const shodanData = await scanWithShodan(ip);
    console.log("Shodan data:", shodanData);

    // Format ports like the old nmap output
    const ports = (shodanData.ports || []).map((port) => ({
      port: String(port),
      protocol: "tcp",
      state: "open",
      service: getServiceName(port),
    }));

    // Format vulnerabilities
    const vulns = (shodanData.vulns || []).map((vuln) => ({
      id: vuln,
      severity: vuln.startsWith("CVE") ? "High" : "Medium",
      url: `https://nvd.nist.gov/vuln/detail/${vuln}`,
    }));

    const resultData = {
      target,
      host:
        shodanData.hostnames?.length > 0
          ? `${shodanData.hostnames[0]} (${ip})`
          : ip,
      ip,
      ports,
      vulns,
      tags: shodanData.tags || [],
      cpes: shodanData.cpes || [],
      hostnames: shodanData.hostnames || [],
      duration: "instant",
      source: "Shodan InternetDB",
      scannedAt: new Date().toISOString(),
    };

    // Save to database
    scansDb
      .insert({
        type: "Network Scan",
        target: target,
        result: resultData,
        findings_count: ports.length + vulns.length,
        severity:
          vulns.length > 0 ? "high" : ports.length > 0 ? "medium" : "info",
        scanned_at: new Date().toISOString(),
      })
      .then(() => console.log("Scan saved"))
      .catch((e) => console.error(e));

    res.json({ success: true, data: resultData });
  } catch (err) {
    console.error("Scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

function getServiceName(port) {
  const services = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
    5900: "vnc",
    11211: "memcached",
    9200: "elasticsearch",
  };
  return services[port] || "unknown";
}

module.exports = router;
