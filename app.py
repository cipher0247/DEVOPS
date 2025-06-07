from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style

app = Flask(__name__)

def check_sql_injection(url):
    payloads = ["'", '"', "' OR '1'='1", '" OR "1"="1']
    vulnerable_params = []
    
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)
    
    for param in query:
        for payload in payloads:
            temp_query = query.copy()
            temp_query[param] = payload
            encoded_query = urlencode(temp_query, doseq=True)
            new_url = urlunparse(parsed_url._replace(query=encoded_query))
            
            try:
                response = requests.get(new_url, timeout=5)
                errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated"]
                if any(error.lower() in response.text.lower() for error in errors):
                    vulnerable_params.append(param)
            except requests.exceptions.RequestException:
                pass
    return vulnerable_params

def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    vulnerable_params = []
    
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)
    
    for param in query:
        temp_query = query.copy()
        temp_query[param] = payload
        encoded_query = urlencode(temp_query, doseq=True)
        new_url = urlunparse(parsed_url._replace(query=encoded_query))
        
        try:
            response = requests.get(new_url, timeout=5)
            if payload in response.text:
                vulnerable_params.append(param)
        except requests.exceptions.RequestException:
            pass
    return vulnerable_params

def check_directory_traversal(url):
    traversal_payloads = ["../", "..\\", "../../etc/passwd", "..\\..\\windows\\win.ini"]
    vulnerable = False
    for payload in traversal_payloads:
        new_url = url + payload
        try:
            response = requests.get(new_url, timeout=5)
            if "root:x" in response.text or "[extensions]" in response.text:
                vulnerable = True
        except requests.exceptions.RequestException:
            pass
    return vulnerable

def generate_report(sql_vulns, xss_vulns, dir_traversal):
    report = []
    if sql_vulns:
        for param in sql_vulns:
            report.append({
                "type": "SQL Injection",
                "param": param,
                "fix": "Use parameterized queries / prepared statements to avoid direct SQL injection."
            })
    else:
        report.append({"type": "SQL Injection", "param": None, "fix": "No SQL Injection vulnerability found."})
    
    if xss_vulns:
        for param in xss_vulns:
            report.append({
                "type": "Cross-Site Scripting (XSS)",
                "param": param,
                "fix": "Sanitize user inputs and encode outputs properly to prevent XSS."
            })
    else:
        report.append({"type": "Cross-Site Scripting (XSS)", "param": None, "fix": "No XSS vulnerability found."})
    
    if dir_traversal:
        report.append({
            "type": "Directory Traversal",
            "param": None,
            "fix": "Validate and sanitize file path inputs to restrict unauthorized file access."
        })
    else:
        report.append({"type": "Directory Traversal", "param": None, "fix": "No Directory Traversal vulnerability found."})
    
    return report




@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        url = request.form['url']
        sql_vulns = check_sql_injection(url)
        xss_vulns = check_xss(url)
        dir_traversal = check_directory_traversal(url)


        report = generate_report(sql_vulns, xss_vulns, dir_traversal)

       
        return render_template('scan_result.html', url=url, report=report)

    else:
        return render_template('scan.html')



if __name__ == "__main__":
    app.run(debug=True)
