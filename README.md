# OSINT & Threat Intelligence Pipeline - Project #24

**Automated Reconnaissance | Intelligence Gathering | MISP-Compatible Reporting**

## Overview

Automated OSINT (Open Source Intelligence) reconnaissance engine that discovers infrastructure, extracts threat indicators, and generates intelligence reports. Combines DNS enumeration, port scanning, certificate transparency logs, reputation checks, and threat analysis.

Built to demonstrate:
- **Threat intelligence expertise** (UN/NGO/AfterQuery hiring need)
- **Security research methodology** (OSINT-based vulnerability discovery)
- **Intelligence platform integration** (MISP export for threat sharing)
- **Infrastructure reconnaissance** (critical for security assessments)

## Features

### 1. Domain Reconnaissance
- DNS A/AAAA record resolution
- MX record enumeration (mail servers)
- NS record discovery (nameservers)
- TXT record analysis (SPF, DMARC, DKIM)
- Subdomain discovery via Certificate Transparency logs

### 2. Infrastructure Discovery
- Port scanning (common services)
- Service identification (SSH, HTTP, SMB, RDP, databases)
- Open port enumeration
- Service banner detection

### 3. Threat Intelligence
- VirusTotal domain reputation checks
- Malicious detection scoring
- WHOIS lookup (registrant info)
- Threat indicator extraction
- IOC (Indicator of Compromise) database

### 4. Intelligence Analysis
- Threat level scoring
- Attack surface assessment
- Risk metrics
- Remediation recommendations

### 5. Intelligence Export
- MISP (Malware Information Sharing Platform) format
- Structured IOC export
- STIX/TAXII compatibility (future)
- Integration with threat feeds

## Technical Architecture

```
osint-threat-intel-pipeline/
├── backend/
│   ├── threat_intel.py           # Main engine (500+ LOC)
│   ├── requirements.txt
│   └── models/
│       ├── IntelligenceTarget
│       ├── ThreatFinding
│       ├── ThreatIndicator
│       └── IntelligenceReport
├── frontend/
│   ├── App.jsx
│   ├── components/
│   │   ├── TargetScanner.jsx      # Initiate scans
│   │   ├── TargetResults.jsx      # View findings
│   │   ├── TargetHistory.jsx      # Scan history
│   │   ├── IndicatorViewer.jsx    # IOC database
│   │   └── MispExporter.jsx       # Export intelligence
│   ├── App.css
│   └── main.jsx
└── docs/
    ├── API.md                     # REST endpoints
    ├── SETUP.md                   # Deployment
    └── TECHNIQUES.md              # OSINT techniques
```

## API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Health check |
| `/api/scan` | POST | Scan target domain |
| `/api/targets` | GET | List all scanned targets |
| `/api/targets/<id>` | GET | Get target report |
| `/api/indicators` | GET | List threat indicators |
| `/api/export/misp/<id>` | GET | Export in MISP format |

### Example: Scan Domain

**Request:**
```bash
curl -X POST http://localhost:5002/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

**Response:**
```json
{
  "target": "example.com",
  "threat_level": "medium",
  "findings_count": 24,
  "threats_detected": 2,
  "findings": [
    {"type": "A_record", "value": "93.184.216.34", "source": "dns"},
    {"type": "MX_record", "value": "mail.example.com", "priority": 10, "source": "dns"},
    {"type": "open_port", "value": 80, "service": "HTTP", "source": "port_scan"},
    {"type": "open_port", "value": 443, "service": "HTTPS", "source": "port_scan"},
    {"type": "subdomains_discovered", "value": ["mail.example.com", "ftp.example.com"], "count": 15, "source": "certificate_transparency"}
  ],
  "threats": [
    {"type": "exposed_service", "indicator": "RDP open", "confidence": 0.7}
  ],
  "misp_export": {...}
}
```

### Example: Get Target Report

**Request:**
```bash
curl http://localhost:5002/api/targets/1
```

**Response:**
```json
{
  "id": 1,
  "domain": "example.com",
  "threat_level": "medium",
  "first_seen": "2024-09-25T10:00:00",
  "last_scan": "2024-09-25T10:15:00",
  "findings": [...],
  "findings_summary": {
    "dns_records": 8,
    "open_ports": 4,
    "subdomains": 15,
    "malicious_detections": 0
  }
}
```

## Reconnaissance Techniques

### 1. DNS Enumeration
Discovers mail servers, nameservers, and DNS records:
```
A records      → IP addresses
MX records     → Email infrastructure
NS records     → Authority servers
TXT records    → Security policies (SPF, DMARC)
CNAME records  → Aliases
```

### 2. Certificate Transparency
Queries CT logs for subdomains:
```
Tool: crt.sh API
Output: All subdomains ever issued SSL certificates
Use: Discover hidden infrastructure
```

### 3. Port Scanning
Checks common service ports:
```
22  → SSH (remote access)
80  → HTTP (web)
443 → HTTPS (secure web)
445 → SMB (file sharing)
3306 → MySQL (database)
5432 → PostgreSQL (database)
3389 → RDP (remote desktop)
```

### 4. Threat Intelligence
Reputation and malware checks:
```
VirusTotal  → Malicious domain detection
WHOIS       → Registrant information
Shodan      → Indexed service details
```

### 5. Threat Indicator Extraction
Identifies IOCs (Indicators of Compromise):
```
Malicious domains
Exposed services
Suspicious infrastructure
Phishing infrastructure
C2 (Command & Control) domains
```

## Use Cases

### 1. UN/NGO Security Assessment
"We need to assess the security posture of NGO infrastructure. This tool performs comprehensive OSINT reconnaissance, identifies exposed services, and generates threat intelligence reports for security hardening."

### 2. AfterQuery Vulnerability Research
"Security research on application targets. This tool automates OSINT reconnaissance to discover attack surface before vulnerability discovery."

### 3. Enterprise Security Assessment
"Pre-engagement reconnaissance for penetration testing. Identifies infrastructure, open services, and potential vulnerabilities."

### 4. Threat Intelligence Analyst
"Intelligence analysts use this to build profiles of threat actors' infrastructure and track malicious domains."

## Installation & Setup

### Backend

```bash
git clone https://github.com/Korir555/osint-threat-intel-pipeline.git
cd osint-threat-intel-pipeline/backend

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Optional: Set API keys for enhanced functionality
export VT_API_KEY="your_virustotal_api_key"
export SHODAN_API_KEY="your_shodan_api_key"

python3 threat_intel.py
# Server runs on http://localhost:5002
```

### Frontend

```bash
cd ../frontend
npm install
npm run dev
# App runs on http://localhost:5173
```

## Intelligence Export Formats

### MISP Event Format
```json
{
  "info": "OSINT: example.com",
  "distribution": 3,
  "threat_level_id": 2,
  "attributes": [
    {"type": "domain", "value": "example.com"},
    {"type": "ip-dst", "value": "93.184.216.34"},
    {"type": "email-src", "value": "admin@example.com"}
  ]
}
```

### Threat Indicators
- **Domains:** Malicious or suspicious domains
- **IPs:** Command & Control servers, infrastructure
- **Emails:** Phishing senders, threat actor accounts
- **Hashes:** Malware file hashes
- **URLs:** Phishing links, drive-by download sites

## Portfolio Context

**Interview Talking Point:**
"I built an automated OSINT reconnaissance engine that discovers infrastructure, extracts threat indicators, and generates intelligence reports compatible with MISP (Malware Information Sharing Platform). It performs DNS enumeration, certificate transparency lookups, port scanning, reputation checks, and threat analysis. The tool automates reconnaissance that security researchers and UN/NGO security teams do manually. This demonstrates security research methodology and threat intelligence expertise."

**GitHub Summary:**
Automated OSINT reconnaissance and threat intelligence pipeline. Performs DNS enumeration, infrastructure discovery, port scanning, reputation analysis, and threat indicator extraction. MISP-compatible export for threat intelligence sharing. 500+ LOC backend, 300+ LOC frontend.

## Project Metrics

| Metric | Value |
|---|---|
| Backend LOC | 500+ |
| Frontend LOC | 300+ |
| API Endpoints | 6 |
| OSINT Techniques | 5+ |
| Database Models | 4 |
| React Components | 5 |
| Build Time | 2-3 weeks |

## Technical Skills Demonstrated

- ✅ **Backend:** Flask, DNS resolution, socket programming, web scraping
- ✅ **Frontend:** React, data visualization, report generation
- ✅ **Security Research:** OSINT methodology, threat analysis, IOC extraction
- ✅ **Intelligence Standards:** MISP format, threat indicator classification
- ✅ **APIs:** VirusTotal, certificate transparency, WHOIS integration

## Next Steps / Extensions

1. **Machine Learning:** Anomaly detection in infrastructure patterns
2. **Advanced Scanning:** Comprehensive port scanning with service fingerprinting
3. **Threat Actor Tracking:** Link IOCs to known threat actors
4. **Automated Reporting:** PDF/HTML intelligence report generation
5. **Graph Visualization:** Infrastructure attack surface mapping
6. **Continuous Monitoring:** Track changes in target infrastructure over time

## Deployment

### Production

```bash
export FLASK_ENV=production
export DATABASE_URL=postgresql://...

heroku create osint-pipeline
git push heroku main
```

### Docker

```bash
docker-compose up --build
```

## Hiring Manager Notes

**Why hire for this project:**
- Demonstrates threat intelligence and research methodology
- Shows OSINT expertise (valued by UN/NGO/security research roles)
- Proves ability to integrate multiple data sources
- Aligns with modern intelligence platform standards (MISP)
- Interview signal: Candidate understands reconnaissance and intelligence gathering

---

**Built by:** Emmanuel Kibet Korir (Trevor)  
**Portfolio:** [korir555.github.io/cybersecurity-portfolio](https://korir555.github.io/cybersecurity-portfolio)  
**GitHub:** [Korir555/osint-threat-intel-pipeline](https://github.com/Korir555/osint-threat-intel-pipeline)  
**Date:** December 2026
