
from flask import Flask, render_template, request, jsonify, send_file
import sqlite3, requests, socket, ipaddress, json, io, datetime, os
from urllib.parse import urlparse
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
DB = os.path.join(os.path.dirname(__file__), "scanner.db")
TIMEOUT = 8
USER_AGENT = "SafeWebSecurityScanner/1.0 (authorized passive assessment)"

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            created_at TEXT NOT NULL,
            score INTEGER NOT NULL,
            findings_json TEXT NOT NULL
        )""")

def validate_target(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False, "Only http:// and https:// URLs are allowed."

    host = p.hostname
    try:
        infos = socket.getaddrinfo(host, None)
        ips = {x[4][0] for x in infos}
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if (addr.is_private or addr.is_loopback or addr.is_link_local or
                addr.is_multicast or addr.is_reserved or addr.is_unspecified):
                return False, "The target resolves to a private/reserved network address."
    except socket.gaierror:
        return False, "The hostname could not be resolved."
    return True, ""

def finding(name, severity, description, why, remediation, component, owasp=""):
    return {
        "name": name, "severity": severity, "description": description,
        "why": why, "remediation": remediation, "component": component,
        "owasp": owasp
    }

def scan(url):
    ok, msg = validate_target(url)
    if not ok:
        raise ValueError(msg)

    r = requests.get(url, timeout=TIMEOUT, allow_redirects=True,
                     headers={"User-Agent": USER_AGENT}, stream=True)
    headers = {k.lower(): v for k,v in r.headers.items()}
    findings = []

    # HTTPS
    final_url = r.url
    if urlparse(final_url).scheme != "https":
        findings.append(finding(
            "HTTPS not enforced", "High",
            "The final scanned URL uses HTTP rather than HTTPS.",
            "Traffic can be exposed or modified in transit.",
            "Enable HTTPS and redirect HTTP traffic to HTTPS.",
            final_url, "A02: Cryptographic Failures"))

    # Security headers
    required = {
        "content-security-policy": (
            "Content Security Policy missing", "Medium",
            "No Content-Security-Policy response header was observed.",
            "CSP can reduce the impact of some content-injection and XSS attacks.",
            "Define a restrictive CSP appropriate for the application.",
            "A05: Security Misconfiguration"),
        "x-content-type-options": (
            "MIME sniffing protection missing", "Low",
            "X-Content-Type-Options was not observed.",
            "Browsers may attempt MIME sniffing in some situations.",
            "Set X-Content-Type-Options: nosniff.",
            "A05: Security Misconfiguration"),
        "referrer-policy": (
            "Referrer-Policy missing", "Low",
            "No Referrer-Policy header was observed.",
            "Referrer data can disclose URL information to other origins.",
            "Set an appropriate Referrer-Policy such as strict-origin-when-cross-origin.",
            "A05: Security Misconfiguration"),
        "permissions-policy": (
            "Permissions-Policy missing", "Informational",
            "No Permissions-Policy header was observed.",
            "The policy can restrict browser features available to pages.",
            "Define a Permissions-Policy appropriate for the application.",
            "A05: Security Misconfiguration"),
    }
    for h,(name,sev,desc,why,rem,owasp) in required.items():
        if h not in headers:
            findings.append(finding(name,sev,desc,why,rem,final_url,owasp))

    # Clickjacking protection
    xfo = headers.get("x-frame-options","")
    csp = headers.get("content-security-policy","")
    if not xfo and "frame-ancestors" not in csp.lower():
        findings.append(finding(
            "Clickjacking protection missing", "Medium",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
            "A page may be embeddable by another origin and could be exposed to clickjacking.",
            "Use CSP frame-ancestors and/or X-Frame-Options where appropriate.",
            final_url, "A05: Security Misconfiguration"))

    # Server disclosure
    if "server" in headers:
        findings.append(finding(
            "Server header disclosure", "Low",
            f"The response exposes a Server header: {headers['server'][:120]}",
            "Detailed server information can help attackers fingerprint technology.",
            "Minimize unnecessary version/product disclosure in response headers.",
            final_url, "A05: Security Misconfiguration"))

    # CORS indicator
    acao = headers.get("access-control-allow-origin")
    if acao == "*":
        findings.append(finding(
            "Permissive CORS indicator", "Medium",
            "Access-Control-Allow-Origin is set to '*'.",
            "Wildcard CORS can be unsafe for endpoints handling sensitive data.",
            "Use an explicit allowlist of trusted origins where credentials or sensitive data are involved.",
            final_url, "A05: Security Misconfiguration"))

    # Cookies
    for raw in r.headers.get("set-cookie","").split(","):
        if not raw.strip():
            continue
        low = raw.lower()
        cookie_name = raw.split("=",1)[0].strip()[:80]
        if "secure" not in low and urlparse(final_url).scheme == "https":
            findings.append(finding(
                f"Cookie missing Secure flag ({cookie_name})", "Medium",
                "A cookie set by the response does not visibly include the Secure attribute.",
                "Without Secure, a cookie may be sent over an unencrypted connection if HTTP is used.",
                "Set Secure on cookies that should only travel over HTTPS.",
                final_url, "A05: Security Misconfiguration"))
        if "httponly" not in low:
            findings.append(finding(
                f"Cookie missing HttpOnly flag ({cookie_name})", "Low",
                "A cookie set by the response does not visibly include HttpOnly.",
                "HttpOnly reduces exposure of cookies to client-side scripts.",
                "Set HttpOnly for cookies that do not need JavaScript access.",
                final_url, "A05: Security Misconfiguration"))
        if "samesite" not in low:
            findings.append(finding(
                f"Cookie missing SameSite attribute ({cookie_name})", "Low",
                "A cookie set by the response does not visibly include SameSite.",
                "SameSite helps reduce some cross-site request risks.",
                "Set an appropriate SameSite value for the cookie.",
                final_url, "A05: Security Misconfiguration"))

    score = 100
    weights = {"Critical":30, "High":20, "Medium":10, "Low":4, "Informational":1}
    score -= sum(weights.get(x["severity"],0) for x in findings)
    score = max(0, min(100, score))

    return {
        "target": url, "final_url": final_url, "status": r.status_code,
        "score": score, "findings": findings,
        "headers_checked": len(headers),
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("url") or "").strip()
    authorized = data.get("authorized") is True
    if not authorized:
        return jsonify({"error":"You must confirm that you are authorized to scan this target."}), 400
    try:
        result = scan(target)
        with db() as c:
            c.execute("INSERT INTO scans(target,created_at,score,findings_json) VALUES(?,?,?,?)",
                      (target, result["checked_at"], result["score"], json.dumps(result)))
            result["id"] = c.lastrowid
        return jsonify(result)
    except requests.RequestException as e:
        return jsonify({"error":f"Target could not be reached safely: {str(e)[:180]}"}), 502
    except ValueError as e:
        return jsonify({"error":str(e)}), 400
    except Exception as e:
        return jsonify({"error":"Unexpected scanner error. Check the server log."}), 500

@app.get("/api/history")
def history():
    with db() as c:
        rows = c.execute("SELECT id,target,created_at,score,findings_json FROM scans ORDER BY id DESC LIMIT 50").fetchall()
    out=[]
    for r in rows:
        data=json.loads(r["findings_json"])
        counts={s:sum(1 for f in data["findings"] if f["severity"]==s)
                for s in ["Critical","High","Medium","Low"]}
        out.append({"id":r["id"],"target":r["target"],"created_at":r["created_at"],
                    "score":r["score"],"counts":counts})
    return jsonify(out)

@app.get("/api/scan/<int:scan_id>")
def get_scan(scan_id):
    with db() as c:
        row=c.execute("SELECT findings_json FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error":"Scan not found"}),404
    return jsonify(json.loads(row["findings_json"]))

@app.get("/api/report/<int:scan_id>.json")
def json_report(scan_id):
    with db() as c:
        row=c.execute("SELECT findings_json FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row: return jsonify({"error":"Scan not found"}),404
    data=json.loads(row["findings_json"])
    return app.response_class(json.dumps(data,indent=2), mimetype="application/json",
                              headers={"Content-Disposition":f"attachment; filename=scan-{scan_id}.json"})

@app.get("/api/report/<int:scan_id>.pdf")
def pdf_report(scan_id):
    with db() as c:
        row=c.execute("SELECT findings_json FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row: return jsonify({"error":"Scan not found"}),404
    data=json.loads(row["findings_json"])
    buf=io.BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36)
    styles=getSampleStyleSheet()
    story=[Paragraph("Web Application Security Scan Report",styles["Title"]),
           Spacer(1,10),Paragraph(f"Target: {data['target']}",styles["Normal"]),
           Paragraph(f"Final URL: {data['final_url']}",styles["Normal"]),
           Paragraph(f"Security Score: {data['score']}/100",styles["Heading2"]),Spacer(1,10)]
    table_data=[["Severity","Finding","Component"]]
    for f in data["findings"]:
        table_data.append([f["severity"],f["name"],f["component"]])
    if len(table_data)==1:
        table_data.append(["—","No findings detected by these passive checks.","—"])
    t=Table(table_data,colWidths=[70,260,150])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172033")),
                           ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                           ("GRID",(0,0),(-1,-1),0.5,colors.grey),
                           ("VALIGN",(0,0),(-1,-1),"TOP")]))
    story += [t,Spacer(1,15)]
    for f in data["findings"]:
        story += [Paragraph(f"<b>{f['severity']}: {f['name']}</b>",styles["Heading3"]),
                  Paragraph(f"<b>Description:</b> {f['description']}",styles["BodyText"]),
                  Paragraph(f"<b>Why it matters:</b> {f['why']}",styles["BodyText"]),
                  Paragraph(f"<b>Remediation:</b> {f['remediation']}",styles["BodyText"]),
                  Paragraph(f"<b>OWASP:</b> {f['owasp'] or 'N/A'}",styles["BodyText"]),Spacer(1,8)]
    doc.build(story); buf.seek(0)
    return send_file(buf,as_attachment=True,download_name=f"scan-{scan_id}.pdf",mimetype="application/pdf")

if __name__=="__main__":
    init_db()
    app.run(host="127.0.0.1",port=5000,debug=False)
