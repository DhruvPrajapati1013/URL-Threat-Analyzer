from flask import Flask, render_template, request
from urllib.parse import urlparse
from datetime import datetime
from flask import send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import socket
import requests
from bs4 import BeautifulSoup
import re
import os

API_KEY = "ENTER YOUR API KEY"

app = Flask(__name__)

latest_report = {}

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    global latest_report
    
    url = request.form["url"]

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    protocol = parsed_url.scheme

   
    # VirusTotal Submit
    analysis_id = "Not Available"

    try:
        headers = {
            "x-apikey": API_KEY
        }

        submit_url = "https://www.virustotal.com/api/v3/urls"

        data = {
            "url": url
        }

        vt_response = requests.post(
            submit_url,
            headers=headers,
            data=data
        )

        if vt_response.status_code == 200:
            result = vt_response.json()
            analysis_id = result["data"]["id"]
        else:
            analysis_id = "Failed"

    except:
        analysis_id = "Error"
        
    import time

    if analysis_id != "Failed":

        time.sleep(3)

        headers = {
            "x-apikey": API_KEY
        }

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        if report.status_code == 200:

            vt = report.json()

            stats = vt["data"]["attributes"]["stats"]

            malicious = stats["malicious"]
            suspicious = stats["suspicious"]
            harmless = stats["harmless"]

        else:

            malicious = 0
            suspicious = 0
            harmless = 0

    else:

        malicious = 0
        suspicious = 0
        harmless = 0

    # Website Information

    try:
        response = requests.get(url, timeout=5)

        status_code = response.status_code
        final_url = response.url

        soup = BeautifulSoup(response.text, "html.parser")

        if soup.title:
            page_title = soup.title.string.strip()
        else:
            page_title = "No Title Found"

    except requests.exceptions.RequestException:

        return render_template(
            "error.html",
            message="Unable to connect to the website. Please enter a valid URL."
        )

    # HTTPS

    if protocol == "https":
        https_status = "Secure"
    else:
        https_status = "Not Secure"

    # IP Address

    try:
        ip_address = socket.gethostbyname(domain)
    except:
        ip_address = "Unable to detect"

    # Manual URL Analysis

    score = 0
    reasons = []

    suspicious_words = [
        "login",
        "verify",
        "update",
        "bank",
        "free",
        "gift",
        "secure"
    ]

    for word in suspicious_words:

        if word in url.lower():
            score += 20
            reasons.append(f"Suspicious word found: {word}")

    if not url.startswith("https://"):
        score += 20
        reasons.append("Website is not using HTTPS")

    if len(url) > 50:
        score += 20
        reasons.append("URL is very long")

    if "@" in url:
        score += 20
        reasons.append("@ symbol detected")

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 20
        reasons.append("IP Address used instead of domain")

    if score >= 40:
        status = "Suspicious"
    else:
        status = "Safe"

    if score <= 20:
        color = "green"
    elif score <= 40:
        color = "orange"
    else:
        color = "red"
        
    scan_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    
    latest_report = {
    "url": url,
    "domain": domain,
    "ip_address": ip_address,
    "https_status": https_status,
    "status": status,
    "score": score,
    "page_title": page_title,
    "status_code": status_code,
    "final_url": final_url,
    "reasons": reasons
}
    
    if len(reasons) == 0:
        reasons.append("No suspicious indicators found.")

    return render_template(
        "result.html",
        url=url,
        status=status,
        score=score,
        reasons=reasons,
        color=color,
        domain=domain,
        protocol=protocol,
        ip_address=ip_address,
        https_status=https_status,
        status_code=status_code,
        final_url=final_url,
        page_title=page_title,
        analysis_id=analysis_id,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        scan_time=scan_time
    )
    
@app.route("/download")
def download():
    
    global latest_report

    pdf_file = "URL_Threat_Report.pdf"

    doc = SimpleDocTemplate(pdf_file)

    styles = getSampleStyleSheet()
    
    url = latest_report["url"]
    domain = latest_report["domain"]
    ip_address = latest_report["ip_address"]
    https_status = latest_report["https_status"]
    status = latest_report["status"]
    score = latest_report["score"]
    page_title = latest_report["page_title"]
    status_code = latest_report["status_code"]
    final_url = latest_report["final_url"]
    reasons = latest_report["reasons"]

    story = []

    story.append(
        Paragraph("URL Threat Analyzer Report", styles["Title"])
    )

    story.append(
        Paragraph("<br/>", styles["Normal"])
    )

    story.append(
        Paragraph(f"<b>Website:</b> {url}", styles["BodyText"])
    )

    story.append(
        Paragraph(f"<b>Domain:</b> {domain}", styles["BodyText"])
    )

    story.append(
        Paragraph(f"<b>IP Address:</b> {ip_address}", styles["BodyText"])
    )   

    story.append(
        Paragraph(f"<b>HTTPS:</b> {https_status}", styles["BodyText"])
    )

    story.append(
        Paragraph(f"<b>Status:</b> {status}", styles["BodyText"])
    )

    story.append(
        Paragraph(f"<b>Risk Score:</b> {score}/100", styles["BodyText"])
    )

    story.append(
        Paragraph(f"<b>Page Title:</b> {page_title}", styles["BodyText"])
    )

    story.append(
        Paragraph(f"<b>Status Code:</b> {status_code}", styles["BodyText"])
    )

    story.append(
        Paragraph(f"<b>Final URL:</b> {final_url}", styles["BodyText"])
    )

    story.append(
        Paragraph("<br/>", styles["Normal"])
    )

    story.append(
        Paragraph("<b>Reasons</b>", styles["Heading2"])
    )

    for reason in reasons:
        story.append(
            Paragraph("• " + reason, styles["BodyText"])
        )

    doc.build(story)

    return send_file(pdf_file, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)