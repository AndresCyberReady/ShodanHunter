# 🛡️ ShodanHunter - Security Assessment Tool

A professional cybersecurity assessment tool that leverages the Shodan API to perform comprehensive security analysis on IP addresses. ShodanHunter provides detailed threat intelligence, risk assessment, and generates professional HTML security reports.

![CyberReady](cyberready.world.txt)

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Report Features](#-report-features)
- [Security](#-security)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

- **🔍 IP Address Analysis**: Comprehensive security assessment of any IP address using Shodan's database
- **📊 Risk Assessment**: Automated risk scoring and threat level classification (CRITICAL, HIGH, MEDIUM, LOW)
- **🔐 Port Analysis**: Detailed analysis of open ports with risk categorization
- **📄 Professional HTML Reports**: Beautiful, detailed security assessment reports perfect for stakeholders
- **🎯 Security Recommendations**: Actionable, prioritized security recommendations based on findings
- **🌐 Service Detection**: Identifies running services, versions, and banners
- **⚡ Real-time Intelligence**: Leverages Shodan's real-time threat intelligence database

## 📦 Prerequisites

- Python 3.7 or higher
- Shodan API key ([Get one here](https://account.shodan.io/))
- Internet connection

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ShodanHunter.git
cd ShodanHunter
```

### 2. Set Up Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## ⚙️ Configuration

### Setting Up Your Shodan API Key

You have two options to configure your Shodan API key:

#### Option 1: Environment Variable (Recommended)

**macOS/Linux:**
```bash
export SHODAN_API_KEY='your_api_key_here'
```

To make it permanent, add to your `~/.zshrc` or `~/.bashrc`:
```bash
echo 'export SHODAN_API_KEY="your_api_key_here"' >> ~/.zshrc
source ~/.zshrc
```

**Windows (PowerShell):**
```powershell
$env:SHODAN_API_KEY="your_api_key_here"
```

**Windows (Command Prompt):**
```cmd
set SHODAN_API_KEY=your_api_key_here
```

#### Option 2: Config File

1. Copy the example file:
   ```bash
   cp .shodan_api_key.example .shodan_api_key
   ```

2. Edit `.shodan_api_key` and add your API key:
   ```bash
   echo "your_api_key_here" > .shodan_api_key
   ```

> ⚠️ **Important**: The `.shodan_api_key` file is excluded from git via `.gitignore` to prevent accidental commits.

## 🎮 Usage

### Basic Usage

1. Run the script:
   ```bash
   python ShodanHunter.py
   ```

2. You'll see the CyberReady intro screen for 5 seconds

3. Enter the IP address you want to analyze when prompted:
   ```
   Enter an IP address to lookup: 8.8.8.8
   ```

4. The tool will:
   - Query Shodan for information about the IP
   - Display results in the terminal
   - Generate a detailed HTML report (`shodan_report.html`)

5. Open the HTML report in your browser:
   ```bash
   open shodan_report.html  # macOS
   xdg-open shodan_report.html  # Linux
   start shodan_report.html  # Windows
   ```

### Example Output

```
Shodan IP Lookup Tool - Security Assessment
============================================================
Enter an IP address to lookup: 8.8.8.8

============================================================
SHODAN HOST INFORMATION
============================================================
IP: 8.8.8.8
Organization: Google LLC
Operating System: N/A
ISP: Google LLC
Country: United States
City: Mountain View
Last Update: 2024-01-15T10:30:00.000000

Open Ports: 53, 443

✅ HTML Report generated: shodan_report.html
📄 Open the report in your browser to view the detailed security assessment.
```

## 📄 Report Features

The generated HTML report includes:

### Executive Summary
- Target IP address
- Report generation timestamp
- Overall risk score (0-100)
- Risk level classification

### Risk Assessment
- Detailed risk scoring breakdown
- Identified risk factors
- Threat level indicators

### Host Information
- IP address and organization
- Operating system detection
- ISP and geographic location
- Hostnames and last update timestamp

### Port Analysis
- Complete list of open ports
- Risk level for each port (HIGH, MEDIUM, LOW)
- Service descriptions
- Port risk details table

### Service Details & Banners
- Service banners for each open port
- Product and version information
- Transport protocol details
- Raw banner data

### Security Recommendations
- Prioritized recommendations (HIGH, MEDIUM, LOW priority)
- Actionable security improvements
- Best practices and hardening suggestions

## 🔒 Security

### API Key Security

- **Never commit your API key to the repository**
- The `.shodan_api_key` file is automatically excluded via `.gitignore`
- Use environment variables for production deployments
- Rotate your API key if it's ever exposed

### Report Security

- HTML reports may contain sensitive information
- Reports are excluded from git by default
- Review reports before sharing externally

See [SECURITY.md](SECURITY.md) for detailed security information.

## 🐛 Troubleshooting

### "API key not found" Error

**Solution**: Make sure you've set up your API key using one of the methods in the [Configuration](#-configuration) section.

### "Import shodan could not be resolved" Warning

**Solution**: 
1. Make sure you've activated your virtual environment
2. Install dependencies: `pip install -r requirements.txt`
3. In VS Code/Cursor, select the Python interpreter from `venv/bin/python`

### "No results found" or Empty Report

**Possible causes**:
- The IP address may not be in Shodan's database
- The IP address may be private/localhost
- API rate limits may have been reached

### Permission Errors

**Solution**: Make sure you have write permissions in the project directory for report generation.

## 📚 Understanding Risk Levels

- **CRITICAL** (30+ points): Immediate action required. Multiple high-risk ports exposed.
- **HIGH** (20-29 points): Significant security concerns. Several risky services exposed.
- **MEDIUM** (10-19 points): Moderate risk. Some potentially risky services detected.
- **LOW** (<10 points): Minimal risk. Mostly standard services detected.

### High-Risk Ports

Ports that commonly indicate security issues:
- 21 (FTP), 22 (SSH), 23 (Telnet)
- 3389 (RDP), 445 (SMB), 139 (NetBIOS)
- 1433 (MSSQL), 3306 (MySQL), 5432 (PostgreSQL)
- 5900 (VNC), 8080/8443 (Alternative HTTP/HTTPS)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is open source and available under the MIT License.

## 🙏 Acknowledgments

- [Shodan](https://www.shodan.io/) for providing the excellent API
- [shodan-python](https://github.com/achillean/shodan-python) library
- CyberReady for the inspiration

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the [SECURITY.md](SECURITY.md) for security-related questions

---

**⚠️ Disclaimer**: This tool is for authorized security assessments only. Unauthorized scanning of systems you don't own or have permission to test is illegal. Always ensure you have proper authorization before performing security assessments.

---

Made with 🛡️ by CyberReady

