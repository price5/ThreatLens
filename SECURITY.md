# 🔒 Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| Current | ✅ Yes             |

## Reporting a Vulnerability

We take the security of ThreatLens seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please send an email to: **security@threatlens.dev**

### What to Include

Please include the following information in your report:

- **Vulnerability Type**: What type of vulnerability it is
- **Affected Versions**: Which version(s) of ThreatLens are affected
- **Steps to Reproduce**: Clear, step-by-step instructions to reproduce the issue
- **Impact**: What the potential impact of the vulnerability is
- **Proof of Concept**: If available, include a proof of concept
- **Suggested Fix** (optional): Any suggestions for fixing the issue

### Response Timeline

- **Initial Response**: Within 48 hours
- **Detailed Assessment**: Within 7 days
- **Resolution**: As soon as possible based on severity

### Communication

We will:
- Acknowledge receipt of your report within 48 hours
- Keep you informed of our progress
- Notify you when a fix is available
- Credit you in the security advisory (with your permission)

---

## Security Features

ThreatLens includes several security features:

### Data Protection
- **No Data Storage**: Scans are performed in real-time, no user data is stored
- **API Key Security**: VirusTotal API keys are server-side only
- **Input Validation**: All URLs are validated before processing
- **Output Sanitization**: All user-facing content is properly sanitized

### Network Security
- **HTTPS Only**: Production deployments require HTTPS
- **Rate Limiting**: Built-in protection against abuse
- **Error Handling**: No sensitive information leaked in error messages
- **Secure Headers**: Appropriate security headers are set

### Third-Party Security
- **VirusTotal Integration**: Uses VirusTotal's secure API
- **No Third-Party Tracking**: No analytics or tracking scripts
- **Minimal Dependencies**: Reduced attack surface through minimal dependencies

---

## Best Practices for Users

### API Key Security
- Keep your VirusTotal API key confidential
- Never share your API key in public repositories
- Use environment variables for API key storage
- Rotate API keys regularly

### Deployment Security
- Deploy behind HTTPS
- Use reverse proxy with security headers
- Implement proper access controls
- Monitor for unusual activity

### Scanning Security
- Only scan URLs you own or have permission to test
- Be aware of legal implications of security scanning
- Don't scan sensitive or production systems without authorization

---

## Known Security Considerations

### Current Limitations

1. **Client-Side Validation**: Some validation occurs client-side for UX, always validated server-side
2. **VirusTotal Dependency**: Security scanning depends on VirusTotal's availability and accuracy
3. **No Persistent Storage**: Scan history is not maintained (by design for privacy)

### Mitigation Strategies

1. **Server-Side Validation**: All inputs re-validated on the server
2. **Rate Limiting**: Implemented to prevent abuse
3. **Error Handling**: Comprehensive error handling prevents information leakage
4. **Monitoring**: Application monitoring for unusual patterns

---

## Security Updates

### How Updates Are Handled

- **Security Patches**: Prioritized and released as quickly as possible
- **Version Bumping**: Security updates may include version bumps
- **Documentation**: Security advisories published with fixes
- **Notifications**: Users notified of critical security updates

### Staying Informed

- **GitHub Releases**: Subscribe to releases for security updates
- **Security Advisories**: Check GitHub Security Advisories
- **Documentation**: Review security documentation regularly

---

## Responsible Disclosure Policy

### Our Commitment

We are committed to:

- **Prompt Response**: Acknowledging reports within 48 hours
- **Thorough Investigation**: Assessing all reports carefully
- **Timely Fixes**: Releasing patches as quickly as possible
- **Transparency**: Being transparent about security issues and fixes
- **Credit**: Recognizing researchers who discover vulnerabilities (with permission)

### Expectations from Researchers

We ask security researchers to:

- **Report Responsibly**: Use the private disclosure process
- **Provide Details**: Include enough information to understand and reproduce the issue
- **Allow Reasonable Time**: Give us time to investigate and fix the issue before public disclosure
- **Follow Good Faith**: Act in good faith to help us improve security

### Disclosure Timeline

- **Private Disclosure**: Immediately upon report
- **Public Disclosure**: After fix is available (typically within 90 days)
- **Security Advisory**: Published with technical details and mitigation guidance

---

## Threat Model

### What We Protect Against

1. **Data Exposure**: Preventing unauthorized access to scan results
2. **API Key Compromise**: Protecting VirusTotal API keys
3. **Input Attacks**: Preventing injection and malformed input attacks
4. **Denial of Service**: Implementing rate limiting and resource protection
5. **Cross-Site Scripting**: Proper output sanitization and CSP headers

### What We Don't Protect Against

1. **User Actions**: We can't control how users use the tool
2. **Third-Party Services**: Security of VirusTotal's service is their responsibility
3. **Network Attacks**: Basic network-level attacks should be handled at infrastructure level
4. **Social Engineering**: User education is required for social engineering protection

---

## Security Resources

### For Developers
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Security Headers](https://securityheaders.com/)

### For Users
- [How to Stay Safe Online](https://www.staysafeonline.org/)
- [Security Best Practices](https://www.cisa.gov/individuals-and-families/cyber-safety)

### For Security Researchers
- [Vulnerability Disclosure](https://vuls.cert.org/confluence/display/VD)
- [Coordinated Vulnerability Disclosure](https://www.first.org/cvd)

---

## Contact

### Security Team
- **Email**: security@threatlens.dev
- **PGP Key**: Available upon request
- **Response Time**: Within 48 hours

### General Inquiries
- **Email**: contact@threatlens.dev
- **GitHub Issues**: Non-security related issues
- **Discussions**: General questions and community support

---

Thank you for helping keep ThreatLens and its users safe! 🛡️