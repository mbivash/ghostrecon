const express = require("express");
const router = express.Router();
const dns = require("dns").promises;
const net = require("net");
const { scansDb } = require("../database");

async function testZoneTransfer(domain, nameserver) {
  return new Promise((resolve) => {
    const findings = [];
    const socket = new net.Socket();
    let data = Buffer.alloc(0);
    let resolved = false;

    const cleanup = (result) => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve(result);
      }
    };

    socket.setTimeout(8000);

    socket.connect(53, nameserver, () => {
      // Build AXFR query
      const query = buildAXFRQuery(domain);
      socket.write(query);
    });

    socket.on("data", (chunk) => {
      data = Buffer.concat([data, chunk]);
      const bodyStr = data.toString("binary");

      // Check for zone transfer success indicators
      if (
        data.length > 100 &&
        (bodyStr.includes(domain) || data.length > 500)
      ) {
        findings.push({
          type: "DNS Zone Transfer Allowed (AXFR)",
          severity: "Critical",
          owasp: "A05:2021 - Security Misconfiguration",
          detail: `DNS server ${nameserver} allows zone transfer for ${domain}. Attackers can download your complete DNS zone including all subdomains, internal IPs, mail servers and infrastructure details.`,
          evidence: `AXFR query to ${nameserver} for ${domain} returned ${data.length} bytes of zone data`,
          remediation:
            "Restrict zone transfers to authorized secondary DNS servers only. Configure BIND: allow-transfer { trusted-secondaries; }; Never allow transfers from any IP.",
        });
        cleanup(findings);
      }
    });

    socket.on("timeout", () => cleanup([]));
    socket.on("error", () => cleanup([]));
    socket.on("close", () => cleanup([]));

    setTimeout(() => cleanup([]), 8000);
  });
}

function buildAXFRQuery(domain) {
  const labels = domain.split(".");
  let qname = Buffer.alloc(0);

  labels.forEach((label) => {
    const len = Buffer.alloc(1);
    len.writeUInt8(label.length, 0);
    qname = Buffer.concat([qname, len, Buffer.from(label)]);
  });

  qname = Buffer.concat([qname, Buffer.alloc(1)]);

  const header = Buffer.alloc(12);
  header.writeUInt16BE(Math.floor(Math.random() * 65535), 0); // ID
  header.writeUInt16BE(0x0000, 2); // Flags
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(0, 6); // ANCOUNT
  header.writeUInt16BE(0, 8); // NSCOUNT
  header.writeUInt16BE(0, 10); // ARCOUNT

  const qtype = Buffer.alloc(4);
  qtype.writeUInt16BE(252, 0); // AXFR
  qtype.writeUInt16BE(1, 2); // IN class

  const message = Buffer.concat([header, qname, qtype]);
  const length = Buffer.alloc(2);
  length.writeUInt16BE(message.length, 0);

  return Buffer.concat([length, message]);
}

async function checkOpenResolver(nameserver) {
  const findings = [];
  try {
    const resolver = new dns.Resolver();
    resolver.setServers([nameserver]);

    await resolver.resolve4("google.com");

    findings.push({
      type: "Open DNS Resolver Detected",
      severity: "High",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: `DNS server ${nameserver} resolves queries for external domains. Open resolvers can be used for DNS amplification DDoS attacks — attacker sends small queries, your server sends large responses to victims.`,
      evidence: `${nameserver} successfully resolved google.com — open recursive resolution`,
      remediation:
        "Restrict DNS recursion to internal networks only. Configure BIND: recursion yes; allow-recursion { internal-nets; };",
    });
  } catch (e) {}
  return findings;
}

async function checkDNSSEC(domain) {
  const findings = [];
  try {
    await dns.resolve(domain, "DNSKEY");
    // If we get here DNSSEC is configured
  } catch (e) {
    if (e.code === "ENODATA" || e.code === "ENOTFOUND") {
      findings.push({
        type: "DNSSEC Not Configured",
        severity: "Medium",
        owasp: "A02:2021 - Cryptographic Failures",
        detail:
          "DNSSEC is not enabled for this domain. Without DNSSEC, attackers can perform DNS cache poisoning attacks — redirecting users to malicious sites while the URL appears legitimate.",
        evidence: `No DNSKEY records found for ${domain}`,
        remediation:
          "Enable DNSSEC through your domain registrar or DNS provider. Most major registrars support DNSSEC for free.",
      });
    }
  }
  return findings;
}

async function checkWildcardDNS(domain) {
  const findings = [];
  try {
    const randomSubdomain = `ghostrecon-test-${Math.random().toString(36).substring(7)}.${domain}`;
    await dns.resolve4(randomSubdomain);

    findings.push({
      type: "Wildcard DNS Record Detected",
      severity: "Medium",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: `A wildcard DNS record exists for *.${domain}. Any subdomain resolves to an IP address. This can lead to subdomain takeover attacks and makes it difficult to detect malicious subdomains.`,
      evidence: `Random subdomain ${randomSubdomain} resolved successfully`,
      remediation:
        "Remove wildcard DNS records unless specifically needed. Use explicit subdomain records instead of wildcards.",
    });
  } catch (e) {}
  return findings;
}

async function getAllDNSRecords(domain) {
  const records = {};
  const findings = [];

  const recordTypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"];

  for (const type of recordTypes) {
    try {
      const result = await dns.resolve(domain, type);
      records[type] = result;
    } catch (e) {
      records[type] = [];
    }
  }

  // Check for version.bind (DNS server version disclosure)
  try {
    const nsServers = records["NS"] || [];
    for (const ns of nsServers.slice(0, 2)) {
      try {
        const resolver = new dns.Resolver();
        const nsIp = await dns.resolve4(ns);
        if (nsIp.length > 0) {
          resolver.setServers([nsIp[0]]);
          try {
            await resolver.resolve("version.bind", "TXT");
            findings.push({
              type: "DNS Server Version Disclosed",
              severity: "Low",
              owasp: "A05:2021 - Security Misconfiguration",
              detail: `DNS server ${ns} may disclose its version via version.bind query. Attackers use version information to find known exploits for the DNS software.`,
              evidence: `version.bind query to ${ns} returned data`,
              remediation:
                'Disable version disclosure in BIND: version "not disclosed"; in named.conf options.',
            });
          } catch (e) {}
        }
      } catch (e) {}
    }
  } catch (e) {}

  // Check CAA records
  if (!records["CAA"] || records["CAA"].length === 0) {
    findings.push({
      type: "No CAA Records Found",
      severity: "Low",
      owasp: "A02:2021 - Cryptographic Failures",
      detail:
        "No Certificate Authority Authorization (CAA) records found. Without CAA records, any Certificate Authority can issue SSL certificates for your domain, enabling man-in-the-middle attacks.",
      evidence: `No CAA records found for ${domain}`,
      remediation:
        'Add CAA records to restrict which CAs can issue certificates: "0 issue \\"letsencrypt.org\\""',
    });
  }

  // Check for dangling CNAME records
  const cnames = records["CNAME"] || [];
  for (const cname of cnames) {
    try {
      await dns.resolve4(cname);
    } catch (e) {
      if (e.code === "ENOTFOUND") {
        findings.push({
          type: "Dangling CNAME Record",
          severity: "High",
          owasp: "A05:2021 - Security Misconfiguration",
          detail: `CNAME record points to "${cname}" which does not resolve. This is a dangling DNS record that could allow subdomain takeover.`,
          evidence: `CNAME ${domain} → ${cname} — target does not resolve`,
          remediation:
            "Remove or update the dangling CNAME record. Verify the target domain still exists and is under your control.",
        });
      }
    }
  }

  // Check SOA for zone info
  if (records["SOA"] && records["SOA"].length > 0) {
    const soa = records["SOA"][0];
    if (soa && soa.nsname) {
      const soaStr =
        typeof soa === "object" ? JSON.stringify(soa) : soa.toString();
      if (
        soaStr.includes("internal") ||
        soaStr.includes("corp") ||
        soaStr.includes("local")
      ) {
        findings.push({
          type: "Internal Infrastructure Disclosed in SOA",
          severity: "Low",
          owasp: "A05:2021 - Security Misconfiguration",
          detail:
            "SOA record may reveal internal infrastructure naming conventions.",
          evidence: `SOA record: ${soaStr.substring(0, 100)}`,
          remediation:
            "Review SOA record and ensure it does not expose internal naming conventions.",
        });
      }
    }
  }

  return { records, findings };
}

async function enumerateSubdomains(domain, nameservers) {
  const findings = [];
  const foundSubdomains = [];

  const commonSubs = [
    "www",
    "mail",
    "ftp",
    "admin",
    "blog",
    "dev",
    "test",
    "api",
    "app",
    "portal",
    "vpn",
    "remote",
    "staging",
    "beta",
    "old",
    "shop",
    "store",
    "cdn",
    "media",
    "static",
    "assets",
    "dashboard",
    "help",
    "support",
    "docs",
    "status",
    "auth",
    "login",
    "secure",
    "payments",
    "checkout",
    "forum",
    "git",
    "jenkins",
    "jira",
    "confluence",
    "smtp",
    "pop",
    "imap",
    "mx",
    "ns1",
    "ns2",
    "webmail",
    "cpanel",
    "whm",
    "autodiscover",
  ];

  const results = await Promise.all(
    commonSubs.map(async (sub) => {
      const full = `${sub}.${domain}`;
      try {
        const addrs = await dns.resolve4(full);
        return { subdomain: full, ip: addrs[0], found: true };
      } catch (e) {
        try {
          const cnames = await dns.resolveCname(full);
          return { subdomain: full, cname: cnames[0], found: true };
        } catch (e2) {
          return { subdomain: full, found: false };
        }
      }
    }),
  );

  results.filter((r) => r.found).forEach((r) => foundSubdomains.push(r));

  if (foundSubdomains.length > 0) {
    findings.push({
      type: "Subdomains Enumerated via DNS",
      severity: "Info",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: `Found ${foundSubdomains.length} active subdomains via DNS enumeration: ${foundSubdomains.map((s) => s.subdomain).join(", ")}`,
      evidence: `DNS brute force found ${foundSubdomains.length} active subdomains`,
      remediation:
        "Review all discovered subdomains. Ensure no sensitive or forgotten services are exposed.",
    });
  }

  return { findings, subdomains: foundSubdomains };
}

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target) return res.status(400).json({ error: "Domain is required." });

  let domain = target
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .trim();

  console.log("DNS check for:", domain);

  try {
    const results = {
      domain,
      nameservers: [],
      records: {},
      subdomains: [],
      findings: [],
      scannedAt: new Date().toISOString(),
    };

    // Get nameservers first
    let nameservers = [];
    try {
      nameservers = await dns.resolveNs(domain);
      results.nameservers = nameservers;
    } catch (e) {
      return res
        .status(400)
        .json({ error: `Could not resolve domain: ${domain}` });
    }

    // Run all checks in parallel
    console.log("Running DNS checks...");
    const [dnsRecordResult, dnssecFindings, wildcardFindings, subdomainResult] =
      await Promise.all([
        getAllDNSRecords(domain),
        checkDNSSEC(domain),
        checkWildcardDNS(domain),
        enumerateSubdomains(domain, nameservers),
      ]);

    results.records = dnsRecordResult.records;
    results.findings.push(...dnsRecordResult.findings);
    results.findings.push(...dnssecFindings);
    results.findings.push(...wildcardFindings);
    results.findings.push(...subdomainResult.findings);
    results.subdomains = subdomainResult.subdomains;

    // Test zone transfer on each nameserver
    console.log("Testing zone transfers...");
    for (const ns of nameservers.slice(0, 3)) {
      try {
        const nsIps = await dns.resolve4(ns);
        for (const nsIp of nsIps.slice(0, 1)) {
          const ztFindings = await testZoneTransfer(domain, nsIp);
          results.findings.push(...ztFindings);

          const orFindings = await checkOpenResolver(nsIp);
          results.findings.push(...orFindings);
        }
      } catch (e) {}
    }

    // Remove duplicates
    const seen = new Set();
    results.findings = results.findings.filter((f) => {
      if (seen.has(f.type)) return false;
      seen.add(f.type);
      return true;
    });

    results.summary = {
      nameservers: nameservers.length,
      subdomainsFound: results.subdomains.length,
      critical: results.findings.filter((f) => f.severity === "Critical")
        .length,
      high: results.findings.filter((f) => f.severity === "High").length,
      medium: results.findings.filter((f) => f.severity === "Medium").length,
      low: results.findings.filter((f) => f.severity === "Low").length,
      info: results.findings.filter((f) => f.severity === "Info").length,
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
        type: "DNS Security Check",
        userId: req.user?.id,
        target: domain,
        result: results,
        findings_count: results.summary.total,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: results });
  } catch (err) {
    console.error("DNS check error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
