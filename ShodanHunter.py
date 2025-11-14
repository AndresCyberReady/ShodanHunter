##CyberReady
##Shodan API Example

import shodan
import html
from datetime import datetime
import os
import time

def get_api_key():
    """
    Get Shodan API key from environment variable or config file.
    Priority: Environment Variable > Config File
    """
    # First, try to get from environment variable
    api_key = os.getenv('SHODAN_API_KEY')
    
    if api_key:
        return api_key
    
    # If not found in environment, try to read from config file
    config_file = os.path.join(os.path.dirname(__file__), '.shodan_api_key')
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                api_key = f.read().strip()
                if api_key:
                    return api_key
        except Exception:
            pass
    
    return None

# High-risk ports that commonly indicate security issues
HIGH_RISK_PORTS = {
    21: "FTP - Often misconfigured, allows anonymous access",
    22: "SSH - Weak credentials or outdated versions",
    23: "Telnet - Unencrypted, deprecated protocol",
    25: "SMTP - Open mail relay risk",
    135: "MS-RPC - Windows Remote Procedure Call",
    139: "NetBIOS - SMB file sharing",
    445: "SMB - Windows file sharing, often exploited",
    1433: "MSSQL - Database server",
    3306: "MySQL - Database server",
    3389: "RDP - Remote Desktop Protocol",
    5432: "PostgreSQL - Database server",
    5900: "VNC - Remote desktop, often insecure",
    8080: "HTTP-Proxy - Alternative web server",
    8443: "HTTPS-Proxy - Alternative HTTPS server"
}

# Medium-risk ports
MEDIUM_RISK_PORTS = {
    80: "HTTP - Web server",
    443: "HTTPS - Secure web server",
    161: "SNMP - Network management",
    389: "LDAP - Directory services",
    636: "LDAPS - Secure directory services",
    143: "IMAP - Email",
    993: "IMAPS - Secure email",
    110: "POP3 - Email",
    995: "POP3S - Secure email"
}

def assess_port_risk(port):
    """Assess risk level of a port"""
    if port in HIGH_RISK_PORTS:
        return "HIGH", HIGH_RISK_PORTS[port]
    elif port in MEDIUM_RISK_PORTS:
        return "MEDIUM", MEDIUM_RISK_PORTS[port]
    else:
        return "LOW", "Unknown service"

def calculate_overall_risk(host_data):
    """Calculate overall risk score based on findings"""
    risk_score = 0
    risk_factors = []
    
    if 'ports' in host_data:
        for port in host_data['ports']:
            risk_level, _ = assess_port_risk(port)
            if risk_level == "HIGH":
                risk_score += 10
                risk_factors.append(f"High-risk port {port} is exposed")
            elif risk_level == "MEDIUM":
                risk_score += 5
                risk_factors.append(f"Medium-risk port {port} is exposed")
            else:
                risk_score += 1
    
    # Check for version disclosure
    if 'data' in host_data:
        for item in host_data['data']:
            if 'version' in item and item['version']:
                risk_score += 3
                risk_factors.append(f"Version disclosure on port {item.get('port', 'unknown')}")
            if 'product' in item and item['product']:
                risk_score += 2
    
    # Determine risk level
    if risk_score >= 30:
        risk_level = "CRITICAL"
        risk_color = "#dc3545"
    elif risk_score >= 20:
        risk_level = "HIGH"
        risk_color = "#fd7e14"
    elif risk_score >= 10:
        risk_level = "MEDIUM"
        risk_color = "#ffc107"
    else:
        risk_level = "LOW"
        risk_color = "#28a745"
    
    return risk_score, risk_level, risk_color, risk_factors

def get_security_recommendations(host_data):
    """Generate security recommendations based on findings"""
    recommendations = []
    
    if 'ports' in host_data:
        high_risk_ports = [p for p in host_data['ports'] if p in HIGH_RISK_PORTS]
        if high_risk_ports:
            recommendations.append({
                "priority": "HIGH",
                "title": "Close High-Risk Ports",
                "description": f"Consider closing or restricting access to high-risk ports: {', '.join(map(str, high_risk_ports))}. These ports are commonly targeted by attackers."
            })
        
        if 3389 in host_data['ports']:
            recommendations.append({
                "priority": "HIGH",
                "title": "Secure RDP Access",
                "description": "Port 3389 (RDP) is exposed. Ensure RDP is properly secured with strong authentication, network-level authentication enabled, and consider using VPN instead of direct exposure."
            })
        
        if 22 in host_data['ports']:
            recommendations.append({
                "priority": "HIGH",
                "title": "Harden SSH Configuration",
                "description": "Port 22 (SSH) is exposed. Disable password authentication, use key-based authentication, disable root login, and consider changing the default port."
            })
        
        if 445 in host_data['ports'] or 139 in host_data['ports']:
            recommendations.append({
                "priority": "HIGH",
                "title": "Secure SMB/NetBIOS",
                "description": "SMB/NetBIOS ports are exposed. Ensure SMB is properly configured, disable SMBv1, use strong authentication, and restrict access to trusted networks only."
            })
    
    if 'data' in host_data:
        version_disclosed = False
        for item in host_data['data']:
            if 'version' in item and item['version']:
                version_disclosed = True
                break
        
        if version_disclosed:
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Hide Version Information",
                "description": "Version information is being disclosed in service banners. This helps attackers identify vulnerabilities. Configure services to hide or obfuscate version information."
            })
    
    recommendations.append({
        "priority": "MEDIUM",
        "title": "Implement Network Segmentation",
        "description": "Consider implementing network segmentation to limit exposure of services. Use firewalls to restrict access to services based on source IP addresses."
    })
    
    recommendations.append({
        "priority": "MEDIUM",
        "title": "Regular Security Audits",
        "description": "Conduct regular security audits and vulnerability assessments. Keep all services and software up to date with the latest security patches."
    })
    
    recommendations.append({
        "priority": "LOW",
        "title": "Monitor and Log",
        "description": "Implement comprehensive logging and monitoring of all exposed services. Use intrusion detection systems (IDS) and security information and event management (SIEM) tools."
    })
    
    return recommendations

def generate_html_report(host_data, ip_address, output_file="shodan_report.html"):
    """Generate a professional HTML security assessment report"""
    
    # Calculate risk assessment
    risk_score, risk_level, risk_color, risk_factors = calculate_overall_risk(host_data)
    recommendations = get_security_recommendations(host_data)
    
    # Get current timestamp
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Start building HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shodan Security Assessment - {ip_address}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .section h3 {{
            color: #555;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        
        .risk-badge {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 1.2em;
            font-weight: bold;
            color: white;
            background: {risk_color};
            margin: 10px 0;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .info-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .info-card strong {{
            color: #667eea;
            display: block;
            margin-bottom: 5px;
        }}
        
        .port-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 20px 0;
        }}
        
        .port-badge {{
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .port-high {{
            background: #dc3545;
            color: white;
        }}
        
        .port-medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .port-low {{
            background: #28a745;
            color: white;
        }}
        
        .service-detail {{
            background: #f8f9fa;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .service-detail h4 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .banner-data {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            margin-top: 10px;
        }}
        
        .recommendation {{
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid;
        }}
        
        .recommendation-high {{
            background: #fff3cd;
            border-color: #dc3545;
        }}
        
        .recommendation-medium {{
            background: #e7f3ff;
            border-color: #ffc107;
        }}
        
        .recommendation-low {{
            background: #d4edda;
            border-color: #28a745;
        }}
        
        .recommendation h4 {{
            margin-bottom: 10px;
        }}
        
        .recommendation .priority {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .priority-high {{
            background: #dc3545;
            color: white;
        }}
        
        .priority-medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .priority-low {{
            background: #28a745;
            color: white;
        }}
        
        .risk-factors {{
            list-style: none;
            padding: 0;
        }}
        
        .risk-factors li {{
            padding: 10px;
            margin: 5px 0;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        table th, table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        
        table th {{
            background: #667eea;
            color: white;
        }}
        
        table tr:hover {{
            background: #f5f5f5;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Shodan Security Assessment Report</h1>
            <p>Cybersecurity Analysis & Threat Intelligence</p>
        </div>
        
        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <strong>Target IP Address</strong>
                        {html.escape(ip_address)}
                    </div>
                    <div class="info-card">
                        <strong>Report Date</strong>
                        {report_date}
                    </div>
                    <div class="info-card">
                        <strong>Risk Score</strong>
                        {risk_score}/100
                    </div>
                    <div class="info-card">
                        <strong>Overall Risk Level</strong>
                        <span class="risk-badge">{risk_level}</span>
                    </div>
                </div>
            </div>
            
            <!-- Risk Assessment -->
            <div class="section">
                <h2>Risk Assessment</h2>
                <p><strong>Overall Risk Level:</strong> <span class="risk-badge">{risk_level}</span></p>
                <p><strong>Risk Score:</strong> {risk_score}/100</p>
                
                <h3>Risk Factors Identified</h3>
                <ul class="risk-factors">
"""
    
    # Add risk factors
    if risk_factors:
        for factor in risk_factors:
            html_content += f"                    <li>{html.escape(factor)}</li>\n"
    else:
        html_content += "                    <li>No significant risk factors identified</li>\n"
    
    html_content += """                </ul>
            </div>
            
            <!-- Host Information -->
            <div class="section">
                <h2>Host Information</h2>
                <div class="info-grid">
"""
    
    # Add host information
    host_info = [
        ("IP Address", host_data.get('ip_str', 'N/A')),
        ("Organization", host_data.get('org', 'N/A')),
        ("Operating System", host_data.get('os', 'N/A')),
        ("ISP", host_data.get('isp', 'N/A')),
        ("Country", host_data.get('country_name', 'N/A')),
        ("City", host_data.get('city', 'N/A')),
        ("Hostnames", ', '.join(host_data.get('hostnames', [])) if host_data.get('hostnames') else 'N/A'),
        ("Last Update", host_data.get('last_update', 'N/A'))
    ]
    
    for label, value in host_info:
        if value != 'N/A' and value:
            html_content += f"""                    <div class="info-card">
                        <strong>{label}</strong>
                        {html.escape(str(value))}
                    </div>
"""
    
    html_content += """                </div>
            </div>
            
            <!-- Port Analysis -->
            <div class="section">
                <h2>Port Analysis</h2>
"""
    
    if 'ports' in host_data and host_data['ports']:
        html_content += f"                <p><strong>Total Open Ports:</strong> {len(host_data['ports'])}</p>\n"
        html_content += "                <div class=\"port-list\">\n"
        
        # Sort ports by risk level
        sorted_ports = sorted(host_data['ports'], key=lambda p: (
            0 if p in HIGH_RISK_PORTS else (1 if p in MEDIUM_RISK_PORTS else 2),
            p
        ))
        
        for port in sorted_ports:
            risk_level, description = assess_port_risk(port)
            html_content += f"                    <span class=\"port-badge port-{risk_level.lower()}\" title=\"{html.escape(description)}\">Port {port} ({risk_level})</span>\n"
        
        html_content += "                </div>\n"
        
        # Port details table
        html_content += """
                <h3>Port Risk Details</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Risk Level</th>
                            <th>Service Description</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        for port in sorted_ports:
            risk_level, description = assess_port_risk(port)
            html_content += f"""                        <tr>
                            <td><strong>{port}</strong></td>
                            <td><span class="port-badge port-{risk_level.lower()}">{risk_level}</span></td>
                            <td>{html.escape(description)}</td>
                        </tr>
"""
        html_content += """                    </tbody>
                </table>
"""
    else:
        html_content += "                <p>No open ports detected.</p>\n"
    
    html_content += """            </div>
            
            <!-- Service Details -->
            <div class="section">
                <h2>Service Details & Banners</h2>
"""
    
    if 'data' in host_data and host_data['data']:
        for item in host_data['data']:
            port = item.get('port', 'N/A')
            transport = item.get('transport', 'N/A')
            product = item.get('product', 'N/A')
            version = item.get('version', 'N/A')
            banner = item.get('data', 'N/A')
            
            risk_level, _ = assess_port_risk(port)
            
            html_content += f"""                <div class="service-detail">
                    <h4>Port {port} ({transport.upper()}) - <span class="port-badge port-{risk_level.lower()}">{risk_level} Risk</span></h4>
"""
            if product != 'N/A':
                html_content += f"                    <p><strong>Product:</strong> {html.escape(str(product))}</p>\n"
            if version != 'N/A':
                html_content += f"                    <p><strong>Version:</strong> {html.escape(str(version))}</p>\n"
            if banner != 'N/A':
                html_content += f"                    <p><strong>Banner:</strong></p>\n"
                html_content += f"                    <div class=\"banner-data\">{html.escape(str(banner))}</div>\n"
            
            html_content += "                </div>\n"
    else:
        html_content += "                <p>No service banner data available.</p>\n"
    
    html_content += """            </div>
            
            <!-- Security Recommendations -->
            <div class="section">
                <h2>Security Recommendations</h2>
"""
    
    # Sort recommendations by priority
    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_recommendations = sorted(recommendations, key=lambda x: priority_order.get(x['priority'], 3))
    
    for rec in sorted_recommendations:
        priority_class = rec['priority'].lower()
        html_content += f"""                <div class="recommendation recommendation-{priority_class}">
                    <span class="priority priority-{priority_class}">{rec['priority']} PRIORITY</span>
                    <h4>{html.escape(rec['title'])}</h4>
                    <p>{html.escape(rec['description'])}</p>
                </div>
"""
    
    html_content += """            </div>
        </div>
        
        <div class="footer">
            <p>Generated by ShodanHunter - Cybersecurity Assessment Tool</p>
            <p>This report is for security assessment purposes only. Unauthorized access to computer systems is illegal.</p>
        </div>
    </div>
</body>
</html>"""
    
    # Write HTML file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_file

def lookup_ip(api, ip_address, generate_report=True):
    """
    Lookup information about an IP address using Shodan API
    
    Args:
        api: Shodan API object
        ip_address: IP address to lookup
        generate_report: Whether to generate HTML report
    """
    try:
        # Lookup the host
        host = api.host(ip_address)
        
        # Print general info to console
        print("\n" + "="*60)
        print("SHODAN HOST INFORMATION")
        print("="*60)
        print(f"IP: {host['ip_str']}")
        print(f"Organization: {host.get('org', 'n/a')}")
        print(f"Operating System: {host.get('os', 'n/a')}")
        print(f"ISP: {host.get('isp', 'n/a')}")
        print(f"Country: {host.get('country_name', 'n/a')}")
        print(f"City: {host.get('city', 'n/a')}")
        print(f"Last Update: {host.get('last_update', 'n/a')}")
        
        # Print open ports and services
        if 'ports' in host:
            print(f"\nOpen Ports: {', '.join(map(str, host['ports']))}")
        
        # Print all banners
        if 'data' in host and host['data']:
            print("\n" + "-"*60)
            print("SERVICES & BANNERS")
            print("-"*60)
            for item in host['data']:
                print(f"\nPort: {item.get('port', 'n/a')}")
                print(f"Transport: {item.get('transport', 'n/a')}")
                if 'product' in item:
                    print(f"Product: {item.get('product', 'n/a')}")
                if 'version' in item:
                    print(f"Version: {item.get('version', 'n/a')}")
                print(f"Banner:\n{item.get('data', 'n/a')}")
                print("-"*60)
        
        print("\n")
        
        # Generate HTML report
        if generate_report:
            report_file = generate_html_report(host, ip_address)
            print(f"✅ HTML Report generated: {report_file}")
            print(f"📄 Open the report in your browser to view the detailed security assessment.")
        
        return host
        
    except shodan.APIError as e:
        print(f"Error: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def show_intro():
    """Display the CyberReady ASCII art intro screen"""
    try:
        # Try to read the ASCII art file
        art_file = os.path.join(os.path.dirname(__file__), "cyberready.world.txt")
        if os.path.exists(art_file):
            with open(art_file, 'r', encoding='utf-8') as f:
                ascii_art = f.read()
        else:
            # Fallback ASCII art if file not found
            ascii_art = """
        cyberready.world
                           .-.
                          {{#}}
          {}               8@8
        .::::.             888
    @\\/W\/\/W\//@         8@8
     \\/^\/\/^\//     _    )8(    _
      \_O_{}_O_/     (@)__/8@8\__(@)
 ____________________ `~"-=):(=-"~`
|<><><>  |  |  <><><>|     |.|
|<>      |  |      <>|     |C|
|<>      |  |      <>|     |'|
|<>   .--------.   <>|     |.|
|     |   ()   |     |     |Y|
|_____| (O\/O) |_____|     |'|
|     \   /\   /     |     |.|
|------\  \/  /------|     |B|
|       '.__.'       |     |'|
|        |  |        |     |.|
:        |  |        :     |E|
 \       |  |       /      |'|
  \<>    |  |    <>/       |.|
   \<>   |  |   <>/        |R|
    `\<> |  | <>/'         |'|
      `-.|__|.-`           \ /
                            ^
        CyberReady                      
"""
        
        # Clear screen (works on most terminals)
        os.system('clear' if os.name != 'nt' else 'cls')
        
        # Display ASCII art with some styling
        print("\033[96m" + "="*80 + "\033[0m")  # Cyan border
        print("\033[93m" + ascii_art + "\033[0m")  # Yellow text for ASCII art
        print("\033[96m" + "="*80 + "\033[0m")  # Cyan border
        print("\033[92m" + "🛡️  ShodanHunter - Security Assessment Tool" + "\033[0m")
        print("\033[94m" + "Loading..." + "\033[0m\n")
        
        # Wait 5 seconds
        time.sleep(5)
        
        # Clear screen again before continuing
        os.system('clear' if os.name != 'nt' else 'cls')
        
    except Exception as e:
        # If there's any error, just continue without the intro
        pass

def main():
    """Main function to run the Shodan IP lookup tool"""
    
    # Show intro screen
    show_intro()
    
    # Get API key from environment or config file
    api_key = get_api_key()
    
    # Check if API key is set
    if not api_key:
        print("="*60)
        print("❌ ERROR: Shodan API key not found!")
        print("="*60)
        print("\nTo set your API key, use one of these methods:\n")
        print("Method 1 - Environment Variable (Recommended):")
        print("  export SHODAN_API_KEY='your_api_key_here'")
        print("\nMethod 2 - Config File:")
        print("  Create a file named '.shodan_api_key' in the project directory")
        print("  and add your API key as the first line.\n")
        print("Get your API key from: https://account.shodan.io/")
        print("="*60)
        return
    
    # Initialize the API
    try:
        api = shodan.Shodan(api_key)
    except Exception as e:
        print(f"Error initializing Shodan API: {e}")
        return
    
    # Get IP address from user
    print("Shodan IP Lookup Tool - Security Assessment")
    print("="*60)
    ip_address = input("Enter an IP address to lookup: ").strip()
    
    if not ip_address:
        print("Error: IP address cannot be empty.")
        return
    
    # Lookup the IP and generate report
    lookup_ip(api, ip_address, generate_report=True)

if __name__ == "__main__":
    main()
