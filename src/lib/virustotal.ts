// VirusTotal API integration for URL scanning and malware detection
import axios from 'axios';

const VIRUSTOTAL_API_BASE = 'https://www.virustotal.com/vtapi/v2';
const VIRUSTOTAL_API_V3_BASE = 'https://www.virustotal.com/api/v3';

export interface VirusTotalScanResult {
  scanId: string;
  scanDate: string;
  positives: number;
  total: number;
  permalink: string;
  resource: string;
  responseCode: number;
  scans: Record<string, {
    detected: boolean;
    version: string;
    result: string | null;
    update: string;
  }>;
}

export interface VirusTotalUrlReport {
  url: string;
  scanDate: string;
  positives: number;
  total: number;
  permalink: string;
  responseCode: number;
  scans: Record<string, {
    detected: boolean;
    result: string | null;
  }>;
}

export interface VirusTotalDomainReport {
  domain: string;
  responseCode: number;
  resolutions?: Array<{
    ip_address: string;
    last_resolved: string;
  }>;
  subdomains?: string[];
  categories?: Record<string, string[]>;
  whois: string;
  detected_urls?: Array<{
    url: string;
    positives: number;
    scan_date: string;
  }>;
}

export class VirusTotalAPI {
  private apiKey: string;

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  /**
   * Scan a URL using VirusTotal API
   */
  async scanUrl(url: string): Promise<VirusTotalScanResult> {
    try {
      const response = await axios.post(`${VIRUSTOTAL_API_BASE}/url/scan`, 
        `apikey=${this.apiKey}&url=${encodeURIComponent(url)}`,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );
      return response.data;
    } catch (error) {
      console.error('VirusTotal URL scan error:', error);
      throw new Error('Failed to scan URL with VirusTotal');
    }
  }

  /**
   * Get URL scan report from VirusTotal
   */
  async getUrlReport(url: string, scanId?: string): Promise<VirusTotalUrlReport> {
    try {
      const params = new URLSearchParams();
      params.append('apikey', this.apiKey);
      params.append('resource', url);
      if (scanId) {
        params.append('scan', scanId);
      }

      const response = await axios.get(`${VIRUSTOTAL_API_BASE}/url/report?${params}`);
      return response.data;
    } catch (error) {
      console.error('VirusTotal URL report error:', error);
      throw new Error('Failed to get URL report from VirusTotal');
    }
  }

  /**
   * Get domain report from VirusTotal
   */
  async getDomainReport(domain: string): Promise<VirusTotalDomainReport> {
    try {
      const response = await axios.get(
        `${VIRUSTOTAL_API_BASE}/domain/report?apikey=${this.apiKey}&domain=${domain}`
      );
      return response.data;
    } catch (error) {
      console.error('VirusTotal domain report error:', error);
      throw new Error('Failed to get domain report from VirusTotal');
    }
  }

  /**
   * Get file analysis from VirusTotal v3 API
   */
  async getFileAnalysis(hash: string): Promise<any> {
    try {
      const response = await axios.get(
        `${VIRUSTOTAL_API_V3_BASE}/files/${hash}`,
        {
          headers: {
            'x-apikey': this.apiKey
          }
        }
      );
      return response.data;
    } catch (error) {
      console.error('VirusTotal file analysis error:', error);
      throw new Error('Failed to get file analysis from VirusTotal');
    }
  }

  /**
   * Get URL analysis from VirusTotal v3 API
   */
  async getUrlAnalysis(url: string): Promise<any> {
    try {
      const encodedUrl = encodeURIComponent(url);
      const response = await axios.get(
        `${VIRUSTOTAL_API_V3_BASE}/urls/${encodedUrl}`,
        {
          headers: {
            'x-apikey': this.apiKey
          }
        }
      );
      return response.data;
    } catch (error) {
      console.error('VirusTotal URL analysis error:', error);
      throw new Error('Failed to get URL analysis from VirusTotal');
    }
  }

  /**
   * Analyse URL with VirusTotal v3 API
   */
  async analyseUrl(url: string): Promise<any> {
    try {
      const response = await axios.post(
        `${VIRUSTOTAL_API_V3_BASE}/urls`,
        `url=${encodeURIComponent(url)}`,
        {
          headers: {
            'x-apikey': this.apiKey,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );
      return response.data;
    } catch (error) {
      console.error('VirusTotal URL analysis error:', error);
      throw new Error('Failed to analyse URL with VirusTotal');
    }
  }
}

// Helper function to extract domain from URL
export function extractDomain(url: string): string {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch {
    return url;
  }
}

// Helper function to check if URL is safe based on VirusTotal results
export function isUrlSafe(report: VirusTotalUrlReport): { safe: boolean; riskLevel: 'low' | 'medium' | 'high' } {
  const ratio = report.positives / report.total;
  
  if (report.positives === 0) {
    return { safe: true, riskLevel: 'low' };
  } else if (ratio < 0.1) {
    return { safe: true, riskLevel: 'medium' };
  } else {
    return { safe: false, riskLevel: 'high' };
  }
}

// Create singleton instance
let virusTotalAPI: VirusTotalAPI | null = null;

export function getVirusTotalAPI(): VirusTotalAPI {
  if (!virusTotalAPI) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      throw new Error('VIRUSTOTAL_API_KEY environment variable is not set');
    }
    virusTotalAPI = new VirusTotalAPI(apiKey);
  }
  return virusTotalAPI;
}