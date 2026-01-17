// Defines server-side actions for the application.
'use server';

import { VulnerabilityScanner, ScanInput, ScanResult } from '@/lib/scanner';
import { getVirusTotalAPI } from '@/lib/virustotal';

export async function performScan(data: ScanInput): Promise<ScanResult> {
  try {
    const scanner = new VulnerabilityScanner();
    
    // Add a delay to simulate a comprehensive scan for better UX with the progress bar.
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Perform the basic vulnerability scan
    const result = await scanner.scanWebApplication(data);
    
    try {
      // Try to get VirusTotal analysis
      const virusTotalAPI = getVirusTotalAPI();
      const virusTotalResult = await virusTotalAPI.getUrlReport(data.url);
      
      // If VirusTotal detected threats, add them as high-priority vulnerabilities
      if (virusTotalResult.positives > 0) {
        const malwareVulnerability = {
          type: 'Malware/Threat Detection',
          severity: 'High' as const,
          description: `VirusTotal analysis detected malicious content. ${virusTotalResult.positives} out of ${virusTotalResult.total} security engines flagged this URL as dangerous.`,
          potentialImpact: 'This URL may distribute malware, engage in phishing, or participate in other malicious activities that could harm users.',
          remediation: 'Immediately block access to this URL, investigate the source of the compromise, and scan connected systems for malware. Consider reporting the URL to appropriate security authorities.'
        };
        
        // Add malware vulnerability to the beginning of the list for priority
        result.vulnerabilities.unshift(malwareVulnerability);
        
        // Update executive summary to reflect VirusTotal findings
        result.executiveSummary = result.executiveSummary.replace(
          '**VirusTotal Analysis:**\n✅ Clean: No malware detected',
          `**VirusTotal Analysis:**\n⚠️ MALWARE DETECTED: ${virusTotalResult.positives}/${virusTotalResult.total} security engines flagged this URL`
        );
      }
    } catch (virusTotalError) {
      console.warn('VirusTotal analysis unavailable:', virusTotalError);
      // Continue with basic scan if VirusTotal fails
    }
    
    return result;
  } catch (error) {
    console.error("Error performing scan:", error);
    throw new Error("The security scan failed. Please check the application URL and try again.");
  }
}
