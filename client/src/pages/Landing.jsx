import { useState } from "react";

export default function Landing() {
  const [formData, setFormData] = useState({
    name: "Bivash Mondal",
    email: "mbivash407@gmail.com",
    company: "Individual",
    message: "Trusting you with my domain security.",
  });
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitted(true);
  };

  const features = [
    {
      icon: "🔍",
      title: "Web Vulnerability Scanner",
      desc: "XSS, SQL injection, CSRF, open redirects, sensitive files and 15+ more checks with OWASP mapping",
    },
    {
      icon: "🔐",
      title: "SSL/TLS Analysis",
      desc: "Certificate validity, expiry warnings, protocol version, cipher strength and SSL grade",
    },
    {
      icon: "📧",
      title: "Email Security",
      desc: "SPF, DKIM, DMARC verification — find out if your domain can be spoofed right now",
    },
    {
      icon: "🌐",
      title: "API Security Testing",
      desc: "Authentication flaws, rate limiting, CORS, mass assignment, injection in REST APIs",
    },
    {
      icon: "🕵️",
      title: "OSINT Engine",
      desc: "DNS records, WHOIS, subdomains, technology stack, geolocation and threat intelligence",
    },
    {
      icon: "🔑",
      title: "Authenticated Scanning",
      desc: "Log in and scan protected pages — finds vulnerabilities invisible to unauthenticated scanners",
    },
    {
      icon: "📋",
      title: "Compliance Mapping",
      desc: "Map findings to PCI-DSS, ISO 27001 and OWASP Top 10 with pass/fail scores",
    },
    {
      icon: "📄",
      title: "Professional Reports",
      desc: "Executive summary, risk scores, remediation steps — ready to share with clients",
    },
    {
      icon: "⏰",
      title: "Scheduled Scans",
      desc: "Automatic scans daily, weekly or monthly with results saved to history",
    },
  ];

  const pricing = [
    {
      name: "Basic Audit",
      price: "₹4,999",
      period: "one-time",
      color: "#639922",
      features: [
        "Web vulnerability scan",
        "SSL/TLS check",
        "Email security check",
        "PDF report",
        "OWASP mapping",
        "1 domain",
      ],
    },
    {
      name: "Professional",
      price: "₹9,999",
      period: "one-time",
      color: "#7F77DD",
      popular: true,
      features: [
        "Everything in Basic",
        "API security testing",
        "Subdomain takeover scan",
        "Authenticated scanning",
        "Compliance report (PCI-DSS)",
        "OSINT analysis",
        "Up to 3 domains",
      ],
    },
    {
      name: "Monthly Monitor",
      price: "₹2,999",
      period: "per month",
      color: "#BA7517",
      features: [
        "Automated weekly scans",
        "All professional features",
        "Email alerts on new findings",
        "Monthly compliance report",
        "Priority support",
        "Unlimited domains",
      ],
    },
  ];

  const stats = [
    { val: "25+", label: "Security checks" },
    { val: "100%", label: "Automated" },
    { val: "OWASP", label: "Compliant" },
    { val: "24hr", label: "Report delivery" },
  ];

  return (
    <div
      style={{
        background: "#0d0d0f",
        minHeight: "100vh",
        fontFamily: "system-ui, -apple-system, sans-serif",
        color: "#e8e6f0",
      }}
    >
      {/* Nav */}
      <nav
        style={{
          borderBottom: "0.5px solid #1e1e22",
          padding: "0 60px",
          height: "64px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          position: "sticky",
          top: 0,
          background: "rgba(13,13,15,0.95)",
          backdropFilter: "blur(10px)",
          zIndex: 100,
        }}
      >
        <div style={{ fontSize: "20px", fontWeight: "600" }}>
          Ghost<span style={{ color: "#7F77DD" }}>Recon</span>
        </div>
        <div style={{ display: "flex", gap: "32px", alignItems: "center" }}>
          <a
            href="#features"
            style={{ color: "#777", fontSize: "14px", textDecoration: "none" }}
          >
            Features
          </a>
          <a
            href="#pricing"
            style={{ color: "#777", fontSize: "14px", textDecoration: "none" }}
          >
            Pricing
          </a>
          <a
            href="#contact"
            style={{ color: "#777", fontSize: "14px", textDecoration: "none" }}
          >
            Contact
          </a>
          <a
            href="/login"
            style={{
              background: "#7F77DD",
              color: "white",
              padding: "8px 20px",
              borderRadius: "8px",
              fontSize: "14px",
              textDecoration: "none",
              fontWeight: "500",
            }}
          >
            Login
          </a>
        </div>
      </nav>

      {/* Hero */}
      <section
        style={{
          padding: "100px 60px 80px",
          maxWidth: "1100px",
          margin: "0 auto",
        }}
      >
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            background: "#13121f",
            border: "0.5px solid #3C3489",
            borderRadius: "20px",
            padding: "6px 16px",
            marginBottom: "28px",
          }}
        >
          <div
            style={{
              width: "6px",
              height: "6px",
              borderRadius: "50%",
              background: "#1D9E75",
            }}
          />
          <span style={{ fontSize: "12px", color: "#a89ff5" }}>
            Professional Web Security Auditing Platform
          </span>
        </div>

        <h1
          style={{
            fontSize: "56px",
            fontWeight: "700",
            lineHeight: "1.1",
            marginBottom: "24px",
            maxWidth: "700px",
          }}
        >
          Find security vulnerabilities
          <span style={{ color: "#7F77DD" }}> before</span> attackers do
        </h1>

        <p
          style={{
            fontSize: "18px",
            color: "#777",
            lineHeight: "1.7",
            marginBottom: "40px",
            maxWidth: "560px",
          }}
        >
          GhostRecon automatically scans your website for 25+ security
          vulnerabilities, maps findings to OWASP Top 10, PCI-DSS and ISO 27001,
          and delivers professional reports your clients can act on.
        </p>

        <div style={{ display: "flex", gap: "14px", flexWrap: "wrap" }}>
          <a
            href="#contact"
            style={{
              background: "#7F77DD",
              color: "white",
              padding: "14px 32px",
              borderRadius: "10px",
              fontSize: "15px",
              textDecoration: "none",
              fontWeight: "500",
              display: "inline-block",
            }}
          >
            Get a free security audit
          </a>
          <a
            href="#features"
            style={{
              background: "transparent",
              color: "#a89ff5",
              padding: "14px 32px",
              borderRadius: "10px",
              fontSize: "15px",
              textDecoration: "none",
              border: "0.5px solid #3C3489",
              display: "inline-block",
            }}
          >
            See what we check
          </a>
        </div>

        {/* Stats */}
        <div
          style={{
            display: "flex",
            gap: "40px",
            marginTop: "60px",
            flexWrap: "wrap",
          }}
        >
          {stats.map((s) => (
            <div key={s.label}>
              <div
                style={{
                  fontSize: "28px",
                  fontWeight: "700",
                  color: "#7F77DD",
                }}
              >
                {s.val}
              </div>
              <div
                style={{ fontSize: "13px", color: "#555", marginTop: "2px" }}
              >
                {s.label}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Spoofing alert demo */}
      <section
        style={{ padding: "0 60px 80px", maxWidth: "1100px", margin: "0 auto" }}
      >
        <div
          style={{
            background: "#131315",
            border: "0.5px solid #791F1F",
            borderRadius: "16px",
            padding: "32px",
            display: "flex",
            alignItems: "flex-start",
            gap: "20px",
          }}
        >
          <div style={{ fontSize: "32px", flexShrink: 0 }}>⚠️</div>
          <div>
            <div
              style={{
                fontSize: "16px",
                fontWeight: "600",
                color: "#E24B4A",
                marginBottom: "8px",
              }}
            >
              Is your domain vulnerable to email spoofing right now?
            </div>
            <p
              style={{
                fontSize: "14px",
                color: "#777",
                lineHeight: "1.6",
                marginBottom: "16px",
              }}
            >
              Most small business domains have no DMARC policy configured. This
              means anyone can send emails pretending to be from your company —
              tricking your clients into sending payments to the wrong account.
              GhostRecon detects this in seconds.
            </p>
            <a
              href="#contact"
              style={{
                color: "#a89ff5",
                fontSize: "14px",
                textDecoration: "none",
                borderBottom: "1px solid #3C3489",
              }}
            >
              Check your domain for free →
            </a>
          </div>
        </div>
      </section>

      {/* Features */}
      <section
        id="features"
        style={{ padding: "80px 60px", maxWidth: "1100px", margin: "0 auto" }}
      >
        <div style={{ marginBottom: "48px" }}>
          <div
            style={{
              fontSize: "12px",
              color: "#7F77DD",
              textTransform: "uppercase",
              letterSpacing: "2px",
              marginBottom: "12px",
            }}
          >
            What we scan
          </div>
          <h2
            style={{
              fontSize: "36px",
              fontWeight: "700",
              marginBottom: "16px",
            }}
          >
            25+ security checks in every audit
          </h2>
          <p
            style={{
              fontSize: "16px",
              color: "#777",
              maxWidth: "500px",
              lineHeight: "1.6",
            }}
          >
            Every scan covers the OWASP Top 10 and maps findings to compliance
            frameworks used by banks, hospitals and enterprises.
          </p>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, 1fr)",
            gap: "16px",
          }}
        >
          {features.map((f) => (
            <div
              key={f.title}
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                padding: "24px",
                transition: "border-color 0.2s",
              }}
            >
              <div style={{ fontSize: "28px", marginBottom: "12px" }}>
                {f.icon}
              </div>
              <div
                style={{
                  fontSize: "14px",
                  fontWeight: "600",
                  color: "#e8e6f0",
                  marginBottom: "8px",
                }}
              >
                {f.title}
              </div>
              <div
                style={{ fontSize: "13px", color: "#666", lineHeight: "1.6" }}
              >
                {f.desc}
              </div>
            </div>
          ))}
        </div>

        {/* Compliance badges */}
        <div
          style={{
            marginTop: "48px",
            display: "flex",
            gap: "12px",
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <span style={{ fontSize: "12px", color: "#555" }}>Mapped to:</span>
          {["OWASP Top 10", "PCI-DSS v3.2.1", "ISO 27001:2013", "NIST CSF"].map(
            (badge) => (
              <span
                key={badge}
                style={{
                  fontSize: "12px",
                  padding: "4px 12px",
                  borderRadius: "20px",
                  background: "#13121f",
                  color: "#a89ff5",
                  border: "0.5px solid #3C3489",
                }}
              >
                {badge}
              </span>
            ),
          )}
        </div>
      </section>

      {/* How it works */}
      <section
        style={{
          padding: "80px 60px",
          background: "#0a0a0c",
          borderTop: "0.5px solid #1e1e22",
          borderBottom: "0.5px solid #1e1e22",
        }}
      >
        <div style={{ maxWidth: "1100px", margin: "0 auto" }}>
          <div style={{ marginBottom: "48px", textAlign: "center" }}>
            <div
              style={{
                fontSize: "12px",
                color: "#7F77DD",
                textTransform: "uppercase",
                letterSpacing: "2px",
                marginBottom: "12px",
              }}
            >
              How it works
            </div>
            <h2 style={{ fontSize: "36px", fontWeight: "700" }}>
              Security audit in 3 steps
            </h2>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: "32px",
            }}
          >
            {[
              {
                step: "01",
                title: "You share your domain",
                desc: "Tell us your website URL. No installation, no software, no technical knowledge needed.",
              },
              {
                step: "02",
                title: "We scan everything",
                desc: "GhostRecon runs 25+ automated security checks across all pages, forms, APIs and DNS records.",
              },
              {
                step: "03",
                title: "You get a professional report",
                desc: "Receive a detailed PDF report with risk scores, compliance mapping and exact remediation steps within 24 hours.",
              },
            ].map((item) => (
              <div key={item.step} style={{ textAlign: "center" }}>
                <div
                  style={{
                    fontSize: "48px",
                    fontWeight: "700",
                    color: "#1e1e22",
                    marginBottom: "16px",
                  }}
                >
                  {item.step}
                </div>
                <div
                  style={{
                    fontSize: "16px",
                    fontWeight: "600",
                    color: "#e8e6f0",
                    marginBottom: "10px",
                  }}
                >
                  {item.title}
                </div>
                <div
                  style={{ fontSize: "14px", color: "#666", lineHeight: "1.6" }}
                >
                  {item.desc}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section
        id="pricing"
        style={{ padding: "80px 60px", maxWidth: "1100px", margin: "0 auto" }}
      >
        <div style={{ marginBottom: "48px" }}>
          <div
            style={{
              fontSize: "12px",
              color: "#7F77DD",
              textTransform: "uppercase",
              letterSpacing: "2px",
              marginBottom: "12px",
            }}
          >
            Pricing
          </div>
          <h2
            style={{
              fontSize: "36px",
              fontWeight: "700",
              marginBottom: "16px",
            }}
          >
            Simple, transparent pricing
          </h2>
          <p style={{ fontSize: "16px", color: "#777" }}>
            No hidden fees. No subscriptions unless you want continuous
            monitoring.
          </p>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, 1fr)",
            gap: "20px",
          }}
        >
          {pricing.map((plan) => (
            <div
              key={plan.name}
              style={{
                background: "#131315",
                border: plan.popular
                  ? `1px solid ${plan.color}`
                  : "0.5px solid #1e1e22",
                borderRadius: "16px",
                padding: "32px",
                position: "relative",
              }}
            >
              {plan.popular && (
                <div
                  style={{
                    position: "absolute",
                    top: "-12px",
                    left: "50%",
                    transform: "translateX(-50%)",
                    background: plan.color,
                    color: "white",
                    fontSize: "11px",
                    fontWeight: "600",
                    padding: "4px 16px",
                    borderRadius: "20px",
                  }}
                >
                  MOST POPULAR
                </div>
              )}

              <div
                style={{ fontSize: "14px", color: "#777", marginBottom: "8px" }}
              >
                {plan.name}
              </div>
              <div
                style={{
                  fontSize: "36px",
                  fontWeight: "700",
                  color: plan.color,
                  marginBottom: "4px",
                }}
              >
                {plan.price}
              </div>
              <div
                style={{
                  fontSize: "13px",
                  color: "#555",
                  marginBottom: "28px",
                }}
              >
                {plan.period}
              </div>

              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "10px",
                  marginBottom: "32px",
                }}
              >
                {plan.features.map((f) => (
                  <div
                    key={f}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                      fontSize: "13px",
                      color: "#ccc",
                    }}
                  >
                    <span style={{ color: plan.color, flexShrink: 0 }}>✓</span>
                    {f}
                  </div>
                ))}
              </div>

              <a
                href="#contact"
                style={{
                  display: "block",
                  textAlign: "center",
                  background: plan.popular ? plan.color : "transparent",
                  color: plan.popular ? "white" : plan.color,
                  border: `1px solid ${plan.color}`,
                  padding: "12px",
                  borderRadius: "10px",
                  fontSize: "14px",
                  textDecoration: "none",
                  fontWeight: "500",
                }}
              >
                Get started
              </a>
            </div>
          ))}
        </div>

        <div
          style={{
            marginTop: "24px",
            textAlign: "center",
            fontSize: "13px",
            color: "#555",
          }}
        >
          All prices in INR. Custom enterprise pricing available. Contact us for
          bulk discounts.
        </div>
      </section>

      {/* Why trust us */}
      <section
        style={{
          padding: "80px 60px",
          background: "#0a0a0c",
          borderTop: "0.5px solid #1e1e22",
          borderBottom: "0.5px solid #1e1e22",
        }}
      >
        <div
          style={{
            maxWidth: "1100px",
            margin: "0 auto",
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "60px",
            alignItems: "center",
          }}
        >
          <div>
            <div
              style={{
                fontSize: "12px",
                color: "#7F77DD",
                textTransform: "uppercase",
                letterSpacing: "2px",
                marginBottom: "12px",
              }}
            >
              Why GhostRecon
            </div>
            <h2
              style={{
                fontSize: "36px",
                fontWeight: "700",
                marginBottom: "20px",
                lineHeight: "1.2",
              }}
            >
              Enterprise-grade security for Indian businesses
            </h2>
            <p
              style={{
                fontSize: "15px",
                color: "#777",
                lineHeight: "1.7",
                marginBottom: "24px",
              }}
            >
              International security tools cost $100-500/month and are designed
              for Western markets. GhostRecon delivers the same quality at
              prices Indian businesses can afford, with local support you can
              actually reach.
            </p>
            <div
              style={{ display: "flex", flexDirection: "column", gap: "14px" }}
            >
              {[
                "Reports in English with Indian business context",
                "Priced for Indian SMBs — not Silicon Valley startups",
                "OWASP, PCI-DSS and ISO 27001 compliance mapping",
                "Direct WhatsApp support — not a ticket system",
              ].map((item) => (
                <div
                  key={item}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "10px",
                    fontSize: "14px",
                    color: "#ccc",
                  }}
                >
                  <span
                    style={{
                      color: "#1D9E75",
                      marginTop: "2px",
                      flexShrink: 0,
                    }}
                  >
                    ✓
                  </span>
                  {item}
                </div>
              ))}
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "14px",
            }}
          >
            {[
              { label: "Vulnerability checks", val: "25+", color: "#7F77DD" },
              { label: "Compliance frameworks", val: "3", color: "#1D9E75" },
              { label: "Report delivery", val: "24hr", color: "#BA7517" },
              { label: "Satisfaction rate", val: "100%", color: "#639922" },
            ].map((s) => (
              <div
                key={s.label}
                style={{
                  background: "#131315",
                  border: "0.5px solid #1e1e22",
                  borderRadius: "12px",
                  padding: "24px",
                  textAlign: "center",
                }}
              >
                <div
                  style={{
                    fontSize: "32px",
                    fontWeight: "700",
                    color: s.color,
                  }}
                >
                  {s.val}
                </div>
                <div
                  style={{ fontSize: "12px", color: "#555", marginTop: "6px" }}
                >
                  {s.label}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Contact */}
      <section
        id="contact"
        style={{ padding: "80px 60px", maxWidth: "1100px", margin: "0 auto" }}
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "60px",
            alignItems: "start",
          }}
        >
          <div>
            <div
              style={{
                fontSize: "12px",
                color: "#7F77DD",
                textTransform: "uppercase",
                letterSpacing: "2px",
                marginBottom: "12px",
              }}
            >
              Get in touch
            </div>
            <h2
              style={{
                fontSize: "36px",
                fontWeight: "700",
                marginBottom: "20px",
                lineHeight: "1.2",
              }}
            >
              Get a free security audit for your website
            </h2>
            <p
              style={{
                fontSize: "15px",
                color: "#777",
                lineHeight: "1.7",
                marginBottom: "32px",
              }}
            >
              Tell us your website and we will run a basic security check for
              free. No obligation, no sales calls unless you want one.
            </p>

            <div
              style={{ display: "flex", flexDirection: "column", gap: "16px" }}
            >
              {[
                { icon: "📧", label: "Email", val: "mbivash407@gmail.com" },
                { icon: "📱", label: "WhatsApp", val: "Available on request" },
                { icon: "📍", label: "Location", val: "Kolkata, West Bengal" },
              ].map((item) => (
                <div
                  key={item.label}
                  style={{ display: "flex", alignItems: "center", gap: "12px" }}
                >
                  <span style={{ fontSize: "20px" }}>{item.icon}</span>
                  <div>
                    <div style={{ fontSize: "11px", color: "#555" }}>
                      {item.label}
                    </div>
                    <div style={{ fontSize: "14px", color: "#ccc" }}>
                      {item.val}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Contact form */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "16px",
              padding: "32px",
            }}
          >
            {submitted ? (
              <div style={{ textAlign: "center", padding: "40px 0" }}>
                <div style={{ fontSize: "40px", marginBottom: "16px" }}>✅</div>
                <div
                  style={{
                    fontSize: "18px",
                    fontWeight: "600",
                    color: "#1D9E75",
                    marginBottom: "8px",
                  }}
                >
                  Message received!
                </div>
                <div style={{ fontSize: "14px", color: "#777" }}>
                  We will get back to you within 24 hours.
                </div>
              </div>
            ) : (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "16px",
                }}
              >
                <div
                  style={{
                    fontSize: "16px",
                    fontWeight: "600",
                    color: "#e8e6f0",
                    marginBottom: "8px",
                  }}
                >
                  Request a free audit
                </div>

                {[
                  {
                    key: "name",
                    label: "Your name",
                    placeholder: "Rahul Sharma",
                  },
                  {
                    key: "email",
                    label: "Email address",
                    placeholder: "rahul@company.com",
                  },
                  {
                    key: "company",
                    label: "Company / Website",
                    placeholder: "yourwebsite.com",
                  },
                ].map((field) => (
                  <div key={field.key}>
                    <label
                      style={{
                        fontSize: "12px",
                        color: "#666",
                        display: "block",
                        marginBottom: "6px",
                      }}
                    >
                      {field.label}
                    </label>
                    <input
                      type="text"
                      placeholder={field.placeholder}
                      value={formData[field.key]}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          [field.key]: e.target.value,
                        })
                      }
                      style={{
                        width: "100%",
                        padding: "10px 14px",
                        background: "#0d0d0f",
                        border: "0.5px solid #1e1e22",
                        borderRadius: "8px",
                        color: "#e8e6f0",
                        fontSize: "14px",
                        outline: "none",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>
                ))}

                <div>
                  <label
                    style={{
                      fontSize: "12px",
                      color: "#666",
                      display: "block",
                      marginBottom: "6px",
                    }}
                  >
                    Message (optional)
                  </label>
                  <textarea
                    placeholder="Tell us about your security concerns..."
                    value={formData.message}
                    onChange={(e) =>
                      setFormData({ ...formData, message: e.target.value })
                    }
                    rows={3}
                    style={{
                      width: "100%",
                      padding: "10px 14px",
                      background: "#0d0d0f",
                      border: "0.5px solid #1e1e22",
                      borderRadius: "8px",
                      color: "#e8e6f0",
                      fontSize: "14px",
                      outline: "none",
                      resize: "vertical",
                      boxSizing: "border-box",
                      fontFamily: "inherit",
                    }}
                  />
                </div>

                <button
                  onClick={handleSubmit}
                  style={{
                    background: "#7F77DD",
                    color: "white",
                    border: "none",
                    borderRadius: "10px",
                    padding: "14px",
                    fontSize: "15px",
                    fontWeight: "600",
                    cursor: "pointer",
                    width: "100%",
                  }}
                >
                  Get free security audit
                </button>

                <div
                  style={{
                    fontSize: "11px",
                    color: "#444",
                    textAlign: "center",
                  }}
                >
                  No spam. No sales pressure. Just a free security check.
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer
        style={{
          borderTop: "0.5px solid #1e1e22",
          padding: "40px 60px",
          background: "#0a0a0c",
        }}
      >
        <div
          style={{
            maxWidth: "1100px",
            margin: "0 auto",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "20px",
          }}
        >
          <div>
            <div
              style={{
                fontSize: "18px",
                fontWeight: "600",
                marginBottom: "6px",
              }}
            >
              Ghost<span style={{ color: "#7F77DD" }}>Recon</span>
            </div>
            <div style={{ fontSize: "12px", color: "#555" }}>
              Professional Web Security Auditing · Kolkata, India
            </div>
          </div>
          <div style={{ fontSize: "12px", color: "#444" }}>
            © 2026 GhostRecon. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}
