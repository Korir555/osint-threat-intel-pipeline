"""
OSINT & Threat Intelligence Pipeline
Automated reconnaissance and intelligence gathering for security research
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import socket
import dns.resolver
import requests
import json
import re
from datetime import datetime
from collections import defaultdict
import subprocess
import os

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threat_intel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =====================
# CONFIGURATION
# =====================

# API Keys (set via environment variables)
VIRUSTOTAL_API_KEY = os.getenv('VT_API_KEY', '')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')

# =====================
# DATABASE MODELS
# =====================

class IntelligenceTarget(db.Model):
    """Target for OSINT reconnaissance"""
    id = db.Column(db.Integer, primary_key=True)
    target_domain = db.Column(db.String(255), unique=True, nullable=False)
    target_type = db.Column(db.String(50), default='domain')  # domain, ip, organization
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_scan = db.Column(db.DateTime, nullable=True)
    threat_level = db.Column(db.String(20), default='unknown')  # low, medium, high, critical
    findings = db.relationship('ThreatFinding', backref='target', lazy=True, cascade='all, delete-orphan')

class ThreatFinding(db.Model):
    """Individual finding from reconnaissance"""
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('intelligence_target.id'), nullable=False)
    finding_type = db.Column(db.String(100), nullable=False)  # ip, mx, ns, open_port, etc.
    finding_value = db.Column(db.String(500), nullable=False)
    confidence = db.Column(db.Float, default=0.8)
    source = db.Column(db.String(100), nullable=False)  # nmap, dns, virustotal, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    metadata = db.Column(db.Text, nullable=True)  # JSON additional info

class ThreatIndicator(db.Model):
    """Extracted threat indicators (IOCs)"""
    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(50), nullable=False)  # ip, domain, hash, email, etc.
    indicator_value = db.Column(db.String(500), unique=True, nullable=False)
    threat_type = db.Column(db.String(100), nullable=True)  # malware, phishing, botnet, c2, etc.
    vt_detection_ratio = db.Column(db.String(20), nullable=True)  # e.g., "15/72"
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=True)

class IntelligenceReport(db.Model):
    """Generated intelligence report for target"""
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('intelligence_target.id'), nullable=False)
    report_date = db.Column(db.DateTime, default=datetime.utcnow)
    summary = db.Column(db.Text, nullable=True)
    findings_count = db.Column(db.Integer, default=0)
    threat_indicators_count = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)
    recommendations = db.Column(db.Text, nullable=True)  # JSON

# =====================
# OSINT RECONNAISSANCE ENGINE
# =====================

class OsintEngine:
    """Orchestrate OSINT reconnaissance"""
    
    @staticmethod
    def resolve_domain(domain):
        """DNS resolution - A records"""
        findings = []
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                findings.append({
                    'type': 'A_record',
                    'value': str(rdata),
                    'source': 'dns'
                })
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def get_mx_records(domain):
        """Get MX (mail) records"""
        findings = []
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                findings.append({
                    'type': 'MX_record',
                    'value': str(rdata.exchange),
                    'priority': rdata.preference,
                    'source': 'dns'
                })
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def get_ns_records(domain):
        """Get nameservers"""
        findings = []
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                findings.append({
                    'type': 'NS_record',
                    'value': str(rdata),
                    'source': 'dns'
                })
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def get_txt_records(domain):
        """Get TXT records (SPF, DMARC, etc.)"""
        findings = []
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                findings.append({
                    'type': 'TXT_record',
                    'value': txt_value,
                    'source': 'dns'
                })
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def scan_ports(ip, ports=None):
        """Port scanning using nmap-like approach"""
        if not ports:
            ports = [22, 80, 443, 445, 3306, 5432, 8080]
        
        findings = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    findings.append({
                        'type': 'open_port',
                        'value': port,
                        'service': OsintEngine.get_service_name(port),
                        'source': 'port_scan'
                    })
            except:
                pass
        
        return findings
    
    @staticmethod
    def get_service_name(port):
        """Get service name for port"""
        services = {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy',
            25: 'SMTP',
            53: 'DNS',
            3389: 'RDP'
        }
        return services.get(port, 'Unknown')
    
    @staticmethod
    def check_virustotal(domain):
        """Check domain/IP reputation on VirusTotal"""
        if not VIRUSTOTAL_API_KEY:
            return []
        
        findings = []
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                detections = stats.get('malicious', 0)
                total = sum(stats.values())
                
                if detections > 0:
                    findings.append({
                        'type': 'malicious_detection',
                        'value': f"{detections}/{total} vendors flagged",
                        'threat_level': 'high' if detections > 10 else 'medium',
                        'source': 'virustotal'
                    })
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def whois_lookup(domain):
        """WHOIS information"""
        findings = []
        
        try:
            # Use online WHOIS service
            response = requests.get(f"https://whois.arin.net/rest/ip/{domain}.json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'handle' in data:
                    findings.append({
                        'type': 'whois_registration',
                        'value': data.get('handle', 'Unknown'),
                        'organization': data.get('name', 'Unknown'),
                        'source': 'whois'
                    })
        except:
            pass
        
        return findings
    
    @staticmethod
    def check_certificate_transparency(domain):
        """Check Certificate Transparency logs for domain"""
        findings = []
        
        try:
            # Query crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                certs = response.json()
                unique_domains = set()
                
                for cert in certs:
                    domains = cert.get('name_value', '').split('\n')
                    for d in domains:
                        if d and d != domain:
                            unique_domains.add(d)
                
                if unique_domains:
                    findings.append({
                        'type': 'subdomains_discovered',
                        'value': list(unique_domains)[:10],  # Top 10
                        'count': len(unique_domains),
                        'source': 'certificate_transparency'
                    })
        except:
            pass
        
        return findings
    
    @staticmethod
    def scan_target(domain):
        """Complete OSINT scan of target"""
        findings = []
        
        # DNS reconnaissance
        findings.extend(OsintEngine.resolve_domain(domain))
        findings.extend(OsintEngine.get_mx_records(domain))
        findings.extend(OsintEngine.get_ns_records(domain))
        findings.extend(OsintEngine.get_txt_records(domain))
        
        # Get primary IP
        try:
            ip = socket.gethostbyname(domain)
            
            # Port scanning on resolved IP
            findings.extend(OsintEngine.scan_ports(ip))
            
            # Threat intelligence
            findings.extend(OsintEngine.check_virustotal(domain))
            findings.extend(OsintEngine.whois_lookup(ip))
        except:
            pass
        
        # Certificate transparency
        findings.extend(OsintEngine.check_certificate_transparency(domain))
        
        return findings
    
    @staticmethod
    def detect_threats(findings):
        """Analyze findings for threat indicators"""
        threats = []
        
        for finding in findings:
            if finding.get('type') == 'malicious_detection':
                threats.append({
                    'type': 'malicious_domain',
                    'indicator': finding.get('value'),
                    'confidence': 0.9
                })
            
            if finding.get('type') == 'open_port':
                if finding.get('value') in [445, 3389]:  # SMB, RDP
                    threats.append({
                        'type': 'exposed_service',
                        'indicator': f"{finding.get('service')} open",
                        'confidence': 0.7
                    })
        
        return threats

# =====================
# API ENDPOINTS
# =====================

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'OSINT Threat Intelligence Pipeline'})

@app.route('/api/scan', methods=['POST'])
def scan_target():
    """Scan domain for threat intelligence"""
    data = request.json
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # Check if already in database
    existing = IntelligenceTarget.query.filter_by(target_domain=target).first()
    if not existing:
        target_obj = IntelligenceTarget(target_domain=target)
        db.session.add(target_obj)
        db.session.flush()
    else:
        target_obj = existing
    
    # Run OSINT scan
    findings = OsintEngine.scan_target(target)
    threats = OsintEngine.detect_threats(findings)
    
    # Calculate threat level
    threat_level = 'low'
    if len(threats) >= 2:
        threat_level = 'high'
    elif len(threats) == 1:
        threat_level = 'medium'
    
    target_obj.last_scan = datetime.utcnow()
    target_obj.threat_level = threat_level
    
    # Save findings
    for finding in findings:
        intel_finding = ThreatFinding(
            target_id=target_obj.id,
            finding_type=finding.get('type'),
            finding_value=str(finding.get('value')),
            source=finding.get('source'),
            metadata=json.dumps(finding)
        )
        db.session.add(intel_finding)
    
    # Save threat indicators
    for threat in threats:
        indicator = ThreatIndicator(
            indicator_type=threat.get('type'),
            indicator_value=threat.get('indicator'),
            threat_type='reconnaissance_target'
        )
        db.session.add(indicator)
    
    db.session.commit()
    
    return jsonify({
        'target': target,
        'threat_level': threat_level,
        'findings_count': len(findings),
        'threats_detected': len(threats),
        'findings': findings,
        'threats': threats,
        'misp_export': generate_misp_export(target, findings, threats)
    })

@app.route('/api/targets', methods=['GET'])
def list_targets():
    """List all scanned targets"""
    targets = IntelligenceTarget.query.all()
    
    return jsonify([{
        'id': t.id,
        'domain': t.target_domain,
        'threat_level': t.threat_level,
        'findings': len(t.findings),
        'last_scan': t.last_scan.isoformat() if t.last_scan else None
    } for t in targets])

@app.route('/api/targets/<int:target_id>', methods=['GET'])
def get_target_report(target_id):
    """Get detailed intelligence report for target"""
    target = IntelligenceTarget.query.get(target_id)
    if not target:
        return jsonify({'error': 'Target not found'}), 404
    
    findings_data = []
    for finding in target.findings:
        findings_data.append({
            'type': finding.finding_type,
            'value': finding.finding_value,
            'source': finding.source,
            'confidence': finding.confidence,
            'timestamp': finding.timestamp.isoformat()
        })
    
    return jsonify({
        'id': target.id,
        'domain': target.target_domain,
        'threat_level': target.threat_level,
        'first_seen': target.first_seen.isoformat(),
        'last_scan': target.last_scan.isoformat() if target.last_scan else None,
        'findings': findings_data,
        'findings_summary': {
            'dns_records': len([f for f in findings_data if 'record' in f['type'].lower()]),
            'open_ports': len([f for f in findings_data if f['type'] == 'open_port']),
            'subdomains': len([f for f in findings_data if f['type'] == 'subdomains_discovered']),
            'malicious_detections': len([f for f in findings_data if 'malicious' in f['type'].lower()])
        }
    })

@app.route('/api/indicators', methods=['GET'])
def list_indicators():
    """List all detected threat indicators"""
    indicators = ThreatIndicator.query.all()
    
    return jsonify([{
        'id': i.id,
        'type': i.indicator_type,
        'value': i.indicator_value,
        'threat_type': i.threat_type,
        'first_seen': i.first_seen.isoformat()
    } for i in indicators])

@app.route('/api/export/misp/<int:target_id>', methods=['GET'])
def export_misp_format(target_id):
    """Export intelligence in MISP format"""
    target = IntelligenceTarget.query.get(target_id)
    if not target:
        return jsonify({'error': 'Target not found'}), 404
    
    misp_event = {
        'info': f'OSINT Reconnaissance: {target.target_domain}',
        'distribution': 3,
        'threat_level_id': 2,
        'analysis': 2,
        'attributes': []
    }
    
    for finding in target.findings:
        misp_event['attributes'].append({
            'type': 'domain' if finding.finding_type == 'A_record' else 'text',
            'value': finding.finding_value,
            'comment': finding.finding_type
        })
    
    return jsonify(misp_event)

def generate_misp_export(domain, findings, threats):
    """Generate MISP-compatible event"""
    return {
        'info': f'OSINT: {domain}',
        'attributes': [
            {'type': 'domain', 'value': domain},
            *[{'type': 'ip-dst', 'value': f['value']} for f in findings if f.get('type') == 'A_record']
        ]
    }

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5002)
