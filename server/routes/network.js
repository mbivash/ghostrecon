const express = require("express");
const router = express.Router();
const net = require("net");
const dns = require("dns").promises;
const { scansDb } = require("../database");

// Top 1000 ports with service names
const PORT_SERVICES = {
  21: {
    name: "FTP",
    risk: "Medium",
    desc: "File Transfer Protocol — unencrypted file transfer",
  },
  22: { name: "SSH", risk: "Low", desc: "Secure Shell — remote access" },
  23: {
    name: "Telnet",
    risk: "Critical",
    desc: "Unencrypted remote access — should never be exposed",
  },
  25: {
    name: "SMTP",
    risk: "Medium",
    desc: "Mail server — check for open relay",
  },
  53: { name: "DNS", risk: "Low", desc: "Domain Name System" },
  80: { name: "HTTP", risk: "Low", desc: "Web server — unencrypted" },
  110: { name: "POP3", risk: "Medium", desc: "Email retrieval — unencrypted" },
  111: {
    name: "RPC",
    risk: "High",
    desc: "Remote Procedure Call — often exploitable",
  },
  119: { name: "NNTP", risk: "Low", desc: "Network News Transfer Protocol" },
  135: {
    name: "MSRPC",
    risk: "High",
    desc: "Microsoft RPC — Windows attack surface",
  },
  139: {
    name: "NetBIOS",
    risk: "High",
    desc: "NetBIOS Session — Windows file sharing",
  },
  143: { name: "IMAP", risk: "Medium", desc: "Email access — unencrypted" },
  161: {
    name: "SNMP",
    risk: "High",
    desc: "Network monitoring — often has default community strings",
  },
  194: { name: "IRC", risk: "Medium", desc: "Internet Relay Chat" },
  389: {
    name: "LDAP",
    risk: "High",
    desc: "Directory service — may expose user data",
  },
  443: { name: "HTTPS", risk: "Low", desc: "Secure web server" },
  445: {
    name: "SMB",
    risk: "Critical",
    desc: "Windows file sharing — EternalBlue exploit target",
  },
  465: { name: "SMTPS", risk: "Low", desc: "Secure mail server" },
  500: { name: "ISAKMP", risk: "Medium", desc: "VPN key exchange" },
  512: {
    name: "rexec",
    risk: "Critical",
    desc: "Remote execution — very dangerous",
  },
  513: {
    name: "rlogin",
    risk: "Critical",
    desc: "Remote login — very dangerous",
  },
  514: { name: "rsh", risk: "Critical", desc: "Remote shell — very dangerous" },
  587: { name: "SMTP", risk: "Low", desc: "Mail submission" },
  631: { name: "IPP", risk: "Medium", desc: "Internet Printing Protocol" },
  636: { name: "LDAPS", risk: "Low", desc: "Secure LDAP" },
  993: { name: "IMAPS", risk: "Low", desc: "Secure IMAP" },
  995: { name: "POP3S", risk: "Low", desc: "Secure POP3" },
  1080: {
    name: "SOCKS",
    risk: "High",
    desc: "SOCKS proxy — potential anonymization",
  },
  1433: {
    name: "MSSQL",
    risk: "Critical",
    desc: "Microsoft SQL Server — database exposed",
  },
  1521: {
    name: "Oracle",
    risk: "Critical",
    desc: "Oracle Database — database exposed",
  },
  2049: {
    name: "NFS",
    risk: "High",
    desc: "Network File System — file sharing",
  },
  2181: {
    name: "ZooKeeper",
    risk: "High",
    desc: "Apache ZooKeeper — coordination service",
  },
  2375: {
    name: "Docker",
    risk: "Critical",
    desc: "Docker daemon — unencrypted, full container control",
  },
  2376: { name: "Docker TLS", risk: "High", desc: "Docker daemon TLS" },
  2379: {
    name: "etcd",
    risk: "Critical",
    desc: "etcd key-value store — Kubernetes secrets exposed",
  },
  3000: {
    name: "Node.js/Grafana",
    risk: "Medium",
    desc: "Common dev server or Grafana dashboard",
  },
  3306: {
    name: "MySQL",
    risk: "Critical",
    desc: "MySQL database — database exposed to internet",
  },
  3389: {
    name: "RDP",
    risk: "Critical",
    desc: "Remote Desktop Protocol — brute force target",
  },
  4200: { name: "Angular", risk: "Low", desc: "Angular dev server" },
  4369: {
    name: "Erlang",
    risk: "High",
    desc: "Erlang port mapper — RabbitMQ attack surface",
  },
  5000: {
    name: "Flask/UPnP",
    risk: "Medium",
    desc: "Common Flask dev server or UPnP",
  },
  5432: {
    name: "PostgreSQL",
    risk: "Critical",
    desc: "PostgreSQL database — database exposed",
  },
  5601: {
    name: "Kibana",
    risk: "High",
    desc: "Kibana dashboard — log data exposed",
  },
  5900: {
    name: "VNC",
    risk: "Critical",
    desc: "Virtual Network Computing — remote desktop",
  },
  5984: {
    name: "CouchDB",
    risk: "Critical",
    desc: "CouchDB — database exposed",
  },
  6379: {
    name: "Redis",
    risk: "Critical",
    desc: "Redis cache — often no auth, full RCE possible",
  },
  6443: {
    name: "Kubernetes",
    risk: "Critical",
    desc: "Kubernetes API server — cluster control",
  },
  7001: {
    name: "WebLogic",
    risk: "Critical",
    desc: "Oracle WebLogic — many critical CVEs",
  },
  7077: { name: "Spark", risk: "High", desc: "Apache Spark master" },
  8080: {
    name: "HTTP Alt",
    risk: "Medium",
    desc: "Alternate HTTP — often dev/admin panels",
  },
  8081: { name: "HTTP Alt", risk: "Medium", desc: "Alternate HTTP port" },
  8443: { name: "HTTPS Alt", risk: "Low", desc: "Alternate HTTPS port" },
  8888: {
    name: "Jupyter",
    risk: "Critical",
    desc: "Jupyter Notebook — often no auth, code execution",
  },
  9000: {
    name: "SonarQube/PHP-FPM",
    risk: "High",
    desc: "SonarQube or PHP-FPM",
  },
  9090: {
    name: "Prometheus",
    risk: "High",
    desc: "Prometheus metrics — internal data exposed",
  },
  9092: { name: "Kafka", risk: "High", desc: "Apache Kafka — message queue" },
  9200: {
    name: "Elasticsearch",
    risk: "Critical",
    desc: "Elasticsearch — database exposed, often no auth",
  },
  9300: {
    name: "Elasticsearch",
    risk: "Critical",
    desc: "Elasticsearch cluster communication",
  },
  10250: {
    name: "Kubelet",
    risk: "Critical",
    desc: "Kubernetes kubelet — node control",
  },
  11211: {
    name: "Memcached",
    risk: "Critical",
    desc: "Memcached — cache exposed, DDoS amplification",
  },
  15672: {
    name: "RabbitMQ",
    risk: "High",
    desc: "RabbitMQ management — message queue admin",
  },
  27017: {
    name: "MongoDB",
    risk: "Critical",
    desc: "MongoDB — database exposed, often no auth",
  },
  27018: { name: "MongoDB", risk: "Critical", desc: "MongoDB shard" },
  50000: { name: "SAP", risk: "High", desc: "SAP Message Server" },
  50070: {
    name: "Hadoop",
    risk: "High",
    desc: "Hadoop NameNode — big data exposed",
  },
};

const TOP_PORTS = Object.keys(PORT_SERVICES).map(Number);

const DEFAULT_CREDENTIALS = {
  FTP: [
    { user: "anonymous", pass: "anonymous" },
    { user: "ftp", pass: "ftp" },
    { user: "admin", pass: "admin" },
  ],
  SSH: [
    { user: "root", pass: "root" },
    { user: "admin", pass: "admin" },
    { user: "ubuntu", pass: "ubuntu" },
  ],
  Telnet: [
    { user: "admin", pass: "admin" },
    { user: "root", pass: "root" },
  ],
  MySQL: [
    { user: "root", pass: "" },
    { user: "root", pass: "root" },
    { user: "admin", pass: "admin" },
  ],
  Redis: [
    { user: "", pass: "" },
    { user: "", pass: "redis" },
  ],
};

function scanPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = "";

    socket.setTimeout(timeout);

    socket.connect(port, host, () => {
      socket.setTimeout(2000);
    });

    socket.on("data", (data) => {
      banner += data.toString("utf8", 0, 256);
      socket.destroy();
    });

    socket.on("connect", () => {
      resolve({ open: true, banner: "" });
    });

    socket.on("data", () => {});

    socket.on("timeout", () => {
      socket.destroy();
      resolve({ open: true, banner: banner.trim() });
    });

    socket.on("error", (err) => {
      socket.destroy();
      if (err.code === "ECONNREFUSED" || err.code === "EHOSTUNREACH") {
        resolve({ open: false });
      } else {
        resolve({ open: false });
      }
    });

    socket.on("close", () => {
      resolve({ open: true, banner: banner.trim() });
    });
  });
}

async function grabBanner(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = "";

    socket.setTimeout(timeout);
    socket.connect(port, host, () => {
      // Send probe for certain protocols
      if (port === 80 || port === 8080) {
        socket.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`);
      } else if (port === 21) {
        // FTP sends banner automatically
      } else if (port === 22) {
        // SSH sends banner automatically
      }
    });

    socket.on("data", (data) => {
      banner += data.toString("utf8", 0, 512);
      socket.destroy();
    });

    socket.on("timeout", () => {
      socket.destroy();
    });
    socket.on("error", () => {
      socket.destroy();
    });
    socket.on("close", () => {
      resolve(banner.trim().substring(0, 200));
    });
  });
}

async function detectServiceVersion(host, port, service) {
  const version = { raw: "", detected: null };

  try {
    const banner = await grabBanner(host, port);
    version.raw = banner;

    // Parse common banners
    if (service === "SSH" && banner.includes("SSH-")) {
      const match = banner.match(/SSH-[\d.]+-([^\s\r\n]+)/);
      if (match) version.detected = match[1];
    } else if (service === "FTP" && banner.length > 0) {
      version.detected = banner.split("\n")[0].substring(0, 100);
    } else if (service === "HTTP" || service === "HTTP Alt") {
      const serverMatch = banner.match(/Server:\s*([^\r\n]+)/i);
      if (serverMatch) version.detected = serverMatch[1].trim();
    } else if (service === "SMTP" && banner.length > 0) {
      version.detected = banner.split("\n")[0].substring(0, 100);
    }
  } catch (e) {}

  return version;
}

function generateFindings(openPorts, target) {
  const findings = [];

  openPorts.forEach((port) => {
    const service = PORT_SERVICES[port.port];
    if (!service) return;

    if (service.risk === "Critical") {
      findings.push({
        type: `Critical Service Exposed: ${service.name} (port ${port.port})`,
        severity: "Critical",
        owasp: "A05:2021 - Security Misconfiguration",
        port: port.port,
        service: service.name,
        detail: `${service.desc}. Port ${port.port} is open and accessible from the internet. ${service.name} on internet-facing servers is a critical security risk.`,
        evidence: `Port ${port.port}/${service.name} open on ${target}${port.banner ? ` — Banner: ${port.banner.substring(0, 100)}` : ""}`,
        remediation: getRemediation(service.name, port.port),
      });
    } else if (service.risk === "High") {
      findings.push({
        type: `High Risk Service Exposed: ${service.name} (port ${port.port})`,
        severity: "High",
        owasp: "A05:2021 - Security Misconfiguration",
        port: port.port,
        service: service.name,
        detail: `${service.desc}. Port ${port.port} is open and accessible from the internet.`,
        evidence: `Port ${port.port}/${service.name} open on ${target}${port.banner ? ` — Banner: ${port.banner.substring(0, 100)}` : ""}`,
        remediation: getRemediation(service.name, port.port),
      });
    } else if (service.risk === "Medium") {
      findings.push({
        type: `Service Exposed: ${service.name} (port ${port.port})`,
        severity: "Medium",
        owasp: "A05:2021 - Security Misconfiguration",
        port: port.port,
        service: service.name,
        detail: `${service.desc}. Port ${port.port} is accessible from the internet.`,
        evidence: `Port ${port.port}/${service.name} open on ${target}`,
        remediation: getRemediation(service.name, port.port),
      });
    }

    // Version-specific findings
    if (port.version?.detected) {
      const versionStr = port.version.detected.toLowerCase();
      if (
        versionStr.includes("openssh") ||
        versionStr.includes("apache") ||
        versionStr.includes("nginx")
      ) {
        findings.push({
          type: `Service Version Disclosed: ${service.name}`,
          severity: "Low",
          owasp: "A06:2021 - Vulnerable and Outdated Components",
          port: port.port,
          detail: `${service.name} version information disclosed in banner. Attackers use version info to find known exploits.`,
          evidence: `Banner: ${port.version.detected}`,
          remediation:
            "Configure service to hide version information in banners.",
        });
      }
    }
  });

  // Check for dangerous combinations
  const openPortNums = openPorts.map((p) => p.port);

  if (openPortNums.includes(6379)) {
    findings.push({
      type: "Redis Exposed — Likely No Authentication",
      severity: "Critical",
      owasp: "A07:2021 - Identification and Authentication Failures",
      port: 6379,
      detail:
        "Redis on port 6379 is exposed. Most Redis installations have no authentication. Attackers can read all cached data, write malicious data, or achieve Remote Code Execution via config manipulation.",
      evidence: "Port 6379 open — Redis default port",
      remediation:
        "Immediately bind Redis to 127.0.0.1. Add requirepass in redis.conf. Use firewall rules to block external access. Never expose Redis to the internet.",
    });
  }

  if (openPortNums.includes(27017)) {
    findings.push({
      type: "MongoDB Exposed — Likely No Authentication",
      severity: "Critical",
      owasp: "A07:2021 - Identification and Authentication Failures",
      port: 27017,
      detail:
        "MongoDB on port 27017 is exposed. Many MongoDB installations have no authentication. This has led to billions of records being exposed and ransomed.",
      evidence: "Port 27017 open — MongoDB default port",
      remediation:
        "Enable MongoDB authentication. Bind to 127.0.0.1 or private network only. Use firewall rules. Enable TLS.",
    });
  }

  if (openPortNums.includes(9200)) {
    findings.push({
      type: "Elasticsearch Exposed — Likely No Authentication",
      severity: "Critical",
      owasp: "A07:2021 - Identification and Authentication Failures",
      port: 9200,
      detail:
        "Elasticsearch on port 9200 is exposed. Default Elasticsearch has no authentication. Billions of records have been leaked from exposed Elasticsearch instances.",
      evidence: "Port 9200 open — Elasticsearch default port",
      remediation:
        "Enable X-Pack security. Bind to private network. Use firewall rules. Add authentication.",
    });
  }

  if (openPortNums.includes(2375)) {
    findings.push({
      type: "Docker Daemon Exposed — Remote Code Execution",
      severity: "Critical",
      owasp: "A05:2021 - Security Misconfiguration",
      port: 2375,
      detail:
        "Docker daemon API is exposed without TLS. Anyone can deploy containers on this server, access all data, and achieve full server compromise.",
      evidence: "Port 2375 open — Docker unencrypted API",
      remediation:
        "Immediately close port 2375. Use TLS on port 2376. Never expose Docker socket to internet.",
    });
  }

  if (openPortNums.includes(8888)) {
    findings.push({
      type: "Jupyter Notebook Exposed — Code Execution",
      severity: "Critical",
      owasp: "A01:2021 - Broken Access Control",
      port: 8888,
      detail:
        "Jupyter Notebook is exposed. Many deployments have no authentication. Attacker can execute arbitrary Python code on the server.",
      evidence: "Port 8888 open — Jupyter Notebook default port",
      remediation:
        "Add password authentication to Jupyter. Bind to localhost. Use reverse proxy with authentication. Never expose Jupyter to internet.",
    });
  }

  return findings;
}

function getRemediation(service, port) {
  const remediations = {
    Telnet:
      "Disable Telnet immediately. Use SSH instead. Telnet transmits all data including passwords in plain text.",
    FTP: "Replace FTP with SFTP or FTPS. If FTP is needed, restrict access by IP and disable anonymous login.",
    SSH: "Restrict SSH access to known IPs. Disable password authentication, use key-based auth. Change default port. Enable fail2ban.",
    RDP: "Move RDP behind VPN. Enable NLA. Restrict access by IP. Use strong passwords and enable MFA. Consider using a bastion host.",
    MySQL:
      "Bind MySQL to localhost (127.0.0.1). Use firewall to block external access. Never expose databases to internet.",
    PostgreSQL:
      "Bind to localhost. Configure pg_hba.conf to restrict connections. Use firewall rules.",
    MongoDB:
      "Enable authentication. Bind to private network. Use firewall rules.",
    Redis:
      "Bind to localhost. Add requirepass. Use firewall rules. Never expose Redis to internet.",
    Elasticsearch:
      "Enable X-Pack security. Bind to private network. Add authentication.",
    SMB: "Block SMB (445) at firewall. Apply all Windows security patches. Disable SMBv1.",
    Docker:
      "Close port 2375. Use TLS on 2376. Never expose Docker to internet.",
    Jupyter: "Add authentication. Bind to localhost. Use reverse proxy.",
    SNMP: "Disable SNMP if not needed. Use SNMPv3 with encryption. Change default community strings.",
    LDAP: "Use LDAPS (636) instead of LDAP (389). Restrict access to authorized hosts only.",
  };
  return (
    remediations[service] ||
    `Restrict access to port ${port} using firewall rules. Only allow trusted IPs.`
  );
}

router.post("/scan", async (req, res) => {
  const { target, consent, scanType = "common" } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target) return res.status(400).json({ error: "Target is required." });

  let host = target
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .trim();

  console.log(`Port scanning ${host}...`);

  try {
    // Resolve hostname to IP
    let ip = host;
    try {
      const addresses = await dns.resolve4(host);
      ip = addresses[0];
    } catch (e) {
      if (!net.isIP(host)) {
        return res
          .status(400)
          .json({ error: `Could not resolve hostname: ${host}` });
      }
    }

    // Select ports to scan
    let portsToScan = TOP_PORTS;
    if (scanType === "quick") {
      portsToScan = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432,
        6379, 8080, 8443, 9200, 27017,
      ];
    } else if (scanType === "full") {
      portsToScan = TOP_PORTS;
    }

    console.log(`Scanning ${portsToScan.length} ports on ${ip}...`);

    // Scan ports in batches
    const openPorts = [];
    const batchSize = 50;
    const timeout = 2000;

    for (let i = 0; i < portsToScan.length; i += batchSize) {
      const batch = portsToScan.slice(i, i + batchSize);
      const results = await Promise.all(
        batch.map(async (port) => {
          const result = await scanPort(ip, port, timeout);
          return { port, ...result };
        }),
      );
      results.filter((r) => r.open).forEach((r) => openPorts.push(r));
    }

    console.log(`Found ${openPorts.length} open ports`);

    // Get service info and banners for open ports
    const enrichedPorts = await Promise.all(
      openPorts.map(async (portResult) => {
        const service = PORT_SERVICES[portResult.port];
        const version = service
          ? await detectServiceVersion(ip, portResult.port, service.name)
          : { raw: "", detected: null };
        return {
          port: portResult.port,
          service: service?.name || "Unknown",
          risk: service?.risk || "Low",
          description: service?.desc || "Unknown service",
          banner: portResult.banner || version.raw.substring(0, 200),
          version: version.detected,
        };
      }),
    );

    // Generate findings
    const findings = generateFindings(enrichedPorts, host);

    const summary = {
      host,
      ip,
      portsScanned: portsToScan.length,
      openPorts: enrichedPorts.length,
      critical: findings.filter((f) => f.severity === "Critical").length,
      high: findings.filter((f) => f.severity === "High").length,
      medium: findings.filter((f) => f.severity === "Medium").length,
      low: findings.filter((f) => f.severity === "Low").length,
      total: findings.length,
    };

    const result = {
      target: host,
      ip,
      openPorts: enrichedPorts,
      findings,
      summary,
      scannedAt: new Date().toISOString(),
    };

    const severity =
      summary.critical > 0
        ? "critical"
        : summary.high > 0
          ? "high"
          : summary.medium > 0
            ? "medium"
            : "info";

    scansDb
      .insert({
        type: "Network Scan",
        userId: req.user?.id,
        target: host,
        result,
        findings_count: findings.length,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: result });
  } catch (err) {
    console.error("Port scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
