// Pure VirusTotal-based web application vulnerability scanner
import { z } from 'zod';
import { getVirusTotalAPI, VirusTotalUrlReport } from './virustotal';

export interface Vulnerability {
  type: string;
  severity: 'High' | 'Medium' | 'Low';
  description: string;
  potentialImpact: string;
  remediation: string;
}

export interface ScanResult {
  vulnerabilities: Vulnerability[];
  executiveSummary: string;
}

export interface ScanInput {
  url: string;
}

export const ScanInputSchema = z.object({
  url: z.string().url().describe('The URL of the web application to scan.'),
});

export class VulnerabilityScanner {
  private analyzeCommonVulnerabilities(url: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const urlObj = new URL(url);
    
    // Check for HTTP usage
    if (urlObj.protocol === 'http:') {
      vulnerabilities.push({
        type: 'Insecure Protocol',
        severity: 'High',
        description: 'The website is using HTTP instead of HTTPS, which means all traffic is unencrypted and can be intercepted.',
        potentialImpact: 'User credentials, session cookies, and sensitive data can be stolen through man-in-the-middle attacks.',
        remediation: 'Implement HTTPS by obtaining an SSL/TLS certificate and redirecting all HTTP traffic to HTTPS.'
      });
    }

    // Check for common vulnerable patterns
    if (url.includes('?') && url.includes('id=')) {
      vulnerabilities.push({
        type: 'Potential SQL Injection',
        severity: 'High',
        description: 'URL parameters detected that could be vulnerable to SQL injection attacks.',
        potentialImpact: 'Attackers could extract, modify, or delete database data, potentially gaining full system access.',
        remediation: 'Use parameterized queries or prepared statements, validate all user input, and implement proper input sanitization.'
      });
    }

    // Check for potential XSS
    if (url.includes('<script>') || url.includes('javascript:')) {
      vulnerabilities.push({
        type: 'Cross-Site Scripting (XSS)',
        severity: 'High',
        description: 'URL contains patterns that could indicate XSS vulnerabilities.',
        potentialImpact: 'Attackers can inject malicious scripts to steal user data, session cookies, or perform unauthorized actions.',
        remediation: 'Implement proper input validation, output encoding, and use Content Security Policy (CSP) headers.'
      });
    }

    // Check for potential path traversal
    if (url.includes('../') || url.includes('..\\')) {
      vulnerabilities.push({
        type: 'Path Traversal',
        severity: 'Medium',
        description: 'URL contains path traversal sequences that could allow access to unauthorized files.',
        potentialImpact: 'Attackers could access sensitive files like configuration files, source code, or system files.',
        remediation: 'Validate all file paths, use a whitelist of allowed files, and implement proper access controls.'
      });
    }

    // Check for long URLs (potential buffer overflow)
    if (url.length > 2048) {
      vulnerabilities.push({
        type: 'Buffer Overflow Risk',
        severity: 'Low',
        description: 'URL is unusually long, which could indicate potential buffer overflow vulnerabilities.',
        potentialImpact: 'Long URLs could crash the server or potentially allow arbitrary code execution.',
        remediation: 'Implement URL length limits and validate all input parameters on the server side.'
      });
    }

    return vulnerabilities;
  }

  private generateSecurityRecommendations(url: string, virusTotalResults: VirusTotalUrlReport | null): Vulnerability[] {
    const recommendations: Vulnerability[] = [];
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // Only add recommendations for specific conditions, not as assumptions
    
    // Check for potential admin panel exposure via common paths
    const adminPaths = ['/admin', '/wp-admin', '/administrator', '/console'];
    if (adminPaths.some(path => url.toLowerCase().includes(path))) {
      recommendations.push({
        type: 'Admin Panel Exposure',
        severity: 'Medium',
        description: `URL may contain administrative access paths that could be exposed.`,
        potentialImpact: 'Administrative interfaces could be targeted by attackers attempting to gain unauthorized access.',
        remediation: 'Implement IP restrictions, strong authentication, and consider moving admin panels to non-standard paths.'
      });
    }

    // Check for potential file upload vulnerabilities
    if (url.toLowerCase().includes('upload') || url.toLowerCase().includes('file')) {
      recommendations.push({
        type: 'File Upload Security',
        severity: 'Medium',
        description: `URL references file upload functionality which requires proper security controls.`,
        potentialImpact: 'Insecure file uploads could allow malicious file execution or data breaches.',
        remediation: 'Validate file types, implement virus scanning, store files outside web root, and use secure file naming conventions.'
      });
    }

    // Check for potential API endpoints
    if (url.toLowerCase().includes('api') || url.toLowerCase().includes('service') || url.toLowerCase().includes('rest')) {
      recommendations.push({
        type: 'API Security',
        severity: 'Low',
        description: `URL appears to reference an API endpoint which should implement proper security controls.`,
        potentialImpact: 'Insecure APIs could lead to data exposure, unauthorized access, or service abuse.',
        remediation: 'Implement API authentication, rate limiting, input validation, and use HTTPS with proper TLS configuration.'
      });
    }

    return recommendations;
  }

  private createExecutiveSummary(url: string, vulnerabilities: Vulnerability[], virusTotalResults: VirusTotalUrlReport | null): string {
    const highCount = vulnerabilities.filter(v => v.severity === 'High').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'Medium').length;
    const lowCount = vulnerabilities.filter(v => v.severity === 'Low').length;

    const virusTotalAnalysis = virusTotalResults 
      ? virusTotalResults.positives === 0 
        ? `✅ Clean: No malware detected by ${virusTotalResults.total} security engines.`
        : `⚠️ Threat Detected: ${virusTotalResults.positives}/${virusTotalResults.total} security engines flagged this URL.`
      : '⚠️ VirusTotal analysis unavailable';

    const riskAssessment = highCount > 0 
      ? `🚨 **Critical Risk:** ${highCount} high severity vulnerabilities require immediate attention.`
      : mediumCount > 0 
        ? `⚠️ **Moderate Risk:** ${mediumCount} medium severity vulnerabilities should be addressed soon.`
        : `✅ **Low Risk:** No critical vulnerabilities detected. Continue monitoring.`;

    return `Security scan completed for ${url}.

**Vulnerability Summary:**
• High Severity: ${highCount}
• Medium Severity: ${mediumCount}  
• Low Severity: ${lowCount}
• Total Issues: ${vulnerabilities.length}

**VirusTotal Analysis:**
${virusTotalAnalysis}

**Risk Assessment:**
${riskAssessment}`;
  }

  async scanWebApplication(input: ScanInput): Promise<ScanResult> {
    try {
      const { url } = input;
      
      // Analyze common web vulnerabilities
      const commonVulnerabilities = this.analyzeCommonVulnerabilities(url);
      
      // Get VirusTotal analysis
      let virusTotalResults: VirusTotalUrlReport | null = null;
      try {
        const virusTotalAPI = getVirusTotalAPI();
        virusTotalResults = await virusTotalAPI.getUrlReport(url);
      } catch (error) {
        console.warn('VirusTotal analysis failed:', error);
      }
      
      // Generate security recommendations
      const recommendations = this.generateSecurityRecommendations(url, virusTotalResults);
      
      // Combine all vulnerabilities
      let allVulnerabilities = [...commonVulnerabilities, ...recommendations];
      
      // Add VirusTotal threats as vulnerabilities if detected
      if (virusTotalResults && virusTotalResults.positives > 0) {
        const malwareVulnerability = {
          type: 'Malware/Threat Detection',
          severity: 'High' as const,
          description: `VirusTotal analysis detected malicious content. ${virusTotalResults.positives} out of ${virusTotalResults.total} security engines flagged this URL as dangerous.`,
          potentialImpact: 'This URL may distribute malware, engage in phishing, or participate in other malicious activities that could harm users.',
          remediation: 'Immediately block access to this URL, investigate the source of the compromise, and scan connected systems for malware. Consider reporting the URL to appropriate security authorities.'
        };
        allVulnerabilities.unshift(malwareVulnerability);
      }
      
      // Generate executive summary
      const executiveSummary = this.createExecutiveSummary(url, allVulnerabilities, virusTotalResults);
      
      return {
        vulnerabilities: allVulnerabilities,
        executiveSummary
      };
    } catch (error) {
      console.error('Error scanning web application:', error);
      throw new Error('Failed to scan web application');
    }
  }
}