# 🔍 ThreatLens – Web Vulnerability Scanner

**Automate. Detect. Secure.**

An advanced, **VirusTotal-powered security tool** designed to **identify, analyze, and report** vulnerabilities in web applications. From **SQL Injection & XSS** to **Malware Detection**, ThreatLens helps developers and security analysts **strengthen their web applications against cyber threats**.

---

## 🚀 Key Features

✅ **Real-time Malware Detection** – Powered by VirusTotal's 70+ security engines  
✅ **Automated Vulnerability Scanning** – Analyze URLs for common security flaws  
✅ **Smart Risk Assessment** – Prioritize vulnerabilities by severity (High/Medium/Low)  
✅ **Detailed Security Reports** – Actionable remediation steps with exportable Markdown reports  
✅ **User-Friendly Interface** – Clean, intuitive UI built with modern React components  
✅ **Zero Database Dependencies** – Lightweight, fast, and easy to deploy  
✅ **TypeScript First** – Full type safety and excellent developer experience  

---

## 🛡️ Security Analysis Capabilities

### **VirusTotal Integration**
- **URL Scanning**: Real-time analysis against VirusTotal's threat database
- **Malware Detection**: Identifies malicious URLs, phishing sites, and malware distribution
- **Multi-Engine Verification**: Results from 70+ security vendors
- **Domain Reputation**: Historical security data and threat intelligence

### **Web Vulnerability Detection**
- 🟢 **Insecure Protocol (HTTP)** - Detects unencrypted connections
- 🔴 **SQL Injection** - Identifies parameter-based injection risks  
- 🟡 **Cross-Site Scripting (XSS)** - Finds script injection vulnerabilities
- 🟣 **Path Traversal** - Detects directory traversal attempts
- 🟠 **Security Headers** - Identifies missing security configurations
- 🔵 **CSRF Protection** - Checks for anti-CSRF implementation

---

## 🎯 Problem Statement

🔴 **80% of cyberattacks** exploit web vulnerabilities like XSS, SQL Injection & malware  
🔴 **Existing tools are expensive & complex** (Burp Suite, OWASP ZAP)  
🔴 **Lack of user-friendly, real-time scanning solutions** for developers & startups  

### 🔓 Solution?
**ThreatLens** – a lightweight, automated, and easy-to-use Web Vulnerability Scanner that integrates VirusTotal's threat intelligence with rule-based analysis, ensuring web applications are **secure by design**.

---

## 🚀 Tech Stack

| Component | Technology |
|-----------|------------|
| **Frontend** | Next.js 15, React 18, TypeScript |
| **UI Framework** | Tailwind CSS, Radix UI, Lucide Icons |
| **Security Scanning** | VirusTotal API, Custom Analysis Engine |
| **State Management** | React Hooks, In-Memory State |
| **Forms** | React Hook Form, Zod Validation |
| **Charts** | Recharts |
| **HTTP Client** | Axios |
| **Build Tool** | Turbopack |

---

## 📋 Prerequisites

- **Node.js 18+** and **npm** installed
- **VirusTotal API Key** (free signup at https://www.virustotal.com/gui/join-us)
- **Modern web browser** (Chrome, Firefox, Safari, Edge)

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-repo/threatlens.git
cd threatlens
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Set Up Environment Variables

```bash
# Copy the example environment file
cp .env.example .env.local

# Edit .env.local and add your VirusTotal API key
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

### 4. Start Development Server

```bash
npm run dev
```

🎉 **Open your browser and navigate to** **http://localhost:9002**

---

## 📖 Usage Guide

### **Basic Scanning**

1. **Enter a URL** in the scan form (e.g., `https://example.com`)
2. **Click "Start Scan"** to begin security analysis
3. **View Results** as the scan progresses with real-time updates
4. **Download Reports** in Markdown format for documentation

### **Understanding Results**

- **🔴 High Severity**: Immediate action required (e.g., malware detected, HTTP usage)
- **🟡 Medium Severity**: Should be addressed soon (e.g., missing security headers)
- **🟢 Low Severity**: Recommendations for improvement (e.g., potential optimizations)

### **Report Features**

- **Executive Summary**: Overview of security posture
- **Vulnerability Details**: In-depth analysis of each issue
- **Remediation Steps**: Actionable guidance to fix vulnerabilities
- **Export Support**: Download complete reports in Markdown format

---

## 🔧 Configuration

### **Environment Variables**

| Variable | Description | Required |
|----------|-------------|----------|
| `VIRUSTOTAL_API_KEY` | Your VirusTotal API key | ✅ Yes |
| `NEXT_PUBLIC_APP_URL` | Base URL for the application | ❌ No |

### **VirusTotal API Setup**

1. **Sign Up**: Visit [VirusTotal](https://www.virustotal.com/gui/join-us)
2. **Get API Key**: Navigate to your profile → API Key
3. **Rate Limits**: Free tier allows 4 requests/minute, 1000 requests/day

---

## 📡 API Endpoints

The application uses VirusTotal's REST API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/vtapi/v2/url/report` | GET | Get URL analysis report |
| `/vtapi/v2/url/scan` | POST | Submit URL for scanning |
| `/vtapi/v2/domain/report` | GET | Get domain reputation |

---

## 🏗️ Project Structure

```
threatlens/
├── src/
│   ├── app/
│   │   ├── actions.ts          # Server-side scan actions
│   │   ├── page.tsx            # Main application page
│   │   └── layout.tsx          # Root layout
│   ├── components/
│   │   ├── ui/                 # Reusable UI components
│   │   └── threatlens/         # Domain-specific components
│   │       ├── logo.tsx
│   │       ├── scan-form.tsx
│   │       ├── scan-report.tsx
│   │       └── vulnerability-details.tsx
│   ├── lib/
│   │   ├── scanner.ts          # Vulnerability scanning logic
│   │   ├── virustotal.ts       # VirusTotal API integration
│   │   ├── types.ts            # TypeScript type definitions
│   │   └── utils.ts            # Utility functions
│   └── hooks/
│       └── use-toast.ts        # Toast notification hook
├── public/                     # Static assets
├── docs/                       # Documentation
├── .env.example               # Environment variables template
├── .gitignore                 # Git ignore patterns
├── package.json               # Dependencies and scripts
├── README.md                  # This file
└── LICENSE                    # MIT License
```

---

## 🚀 Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with Turbopack |
| `npm run build` | Build for production |
| `npm run start` | Start production server |
| `npm run typecheck` | Run TypeScript type checking |
| `npm run lint` | Run ESLint code analysis |

---

## 🔒 Security Features

### **Multi-Layer Analysis**
1. **VirusTotal Integration**: Real-time threat intelligence
2. **Pattern Recognition**: Rule-based vulnerability detection
3. **Protocol Analysis**: HTTPS/HTTP security assessment
4. **URL Structure Analysis**: Parameter injection detection

### **Risk Scoring**
- **High**: Malware detected, HTTP usage, SQL/XSS vulnerabilities
- **Medium**: Missing security headers, CSRF protection gaps
- **Low**: Configuration improvements, best practice recommendations

---

## 📊 Future Roadmap

### **Short-Term**
- ✅ **Real-time Scanning** - Implemented with progress tracking
- ✅ **Export Functionality** - Markdown report downloads
- 🔄 **Additional Vulnerability Types** - CSRF, SSRF, XXE detection

### **Mid-Term**
- 🚀 **Bulk URL Scanning** - Analyze multiple URLs simultaneously
- 🚀 **Historical Reports** - Track security posture over time
- 🚀 **API Rate Limiting** - Intelligent request management

### **Long-Term**
- 🔮 **Integration Support** - CI/CD pipeline integration
- 🔮 **Team Features** - Multi-user collaboration
- 🔮 **Advanced Analytics** - Security trends and insights

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### **Development Guidelines**
- Follow existing code style and patterns
- Add TypeScript types for new functionality
- Include tests for new features
- Update documentation as needed

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🎯 Why Choose ThreatLens?

💡 **Lightweight & Fast** - No database dependencies, scans in seconds  
💡 **VirusTotal Powered** - Leverages industry-leading threat intelligence  
💡 **Developer-Friendly** - Simple setup, clean interface, detailed reports  
💡 **Cost-Effective** - Free to use with VirusTotal's generous free tier  
💡 **Privacy-First** - No data storage, scans are performed in real-time  

---

## 🐛 Troubleshooting

### **Common Issues**

**Q: Scan fails with "Invalid URL" error**
A: Ensure the URL includes the protocol (http:// or https://)

**Q: VirusTotal analysis shows no results**
A: Check your API key in `.env.local` and verify rate limits

**Q: Build process fails**
A: Run `npm install` to ensure all dependencies are up to date

### **Getting Help**

- 📖 Check the [Documentation](./docs/)
- 🐛 Report issues on [GitHub Issues](https://github.com/your-repo/threatlens/issues)
- 💬 Join our [Discussions](https://github.com/your-repo/threatlens/discussions)

---

🔐 **Secure your web applications today with ThreatLens!** 🚀

Made with ❤️ for the developer community