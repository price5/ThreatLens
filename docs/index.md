# 📚 ThreatLens Documentation

## Table of Contents

- [Getting Started](#getting-started)
- [Security Analysis](#security-analysis)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Getting Started

### First Time Setup

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env.local
   # Edit .env.local with your API keys
   ```

3. **Start Development**
   ```bash
   npm run dev
   ```

### Basic Usage

See the main [README](../README.md) for detailed usage instructions.

---

## Security Analysis

### Vulnerability Detection Methods

#### 1. VirusTotal Integration
- **Purpose**: Real-time malware and threat detection
- **Engines**: 70+ security vendors
- **Coverage**: Malware, phishing, malicious URLs

#### 2. Pattern-Based Analysis
- **Protocol Security**: HTTP vs HTTPS detection
- **Parameter Analysis**: SQL injection patterns
- **URL Structure**: XSS and path traversal detection
- **Security Headers**: Missing protection mechanisms

### Severity Classification

| Severity | Description | Examples |
|----------|-------------|----------|
| **High** | Immediate security risk | Malware detected, HTTP usage, SQL/XSS |
| **Medium** | Should be addressed soon | Missing headers, CSRF protection |
| **Low** | Best practice recommendations | Configuration improvements |

---

## API Reference

### VirusTotal API Integration

#### Core Functions

```typescript
// Scan a URL
await virusTotalAPI.scanUrl(url);

// Get analysis report
await virusTotalAPI.getUrlReport(url);

// Domain reputation
await virusTotalAPI.getDomainReport(domain);
```

#### Response Format

```typescript
interface VirusTotalUrlReport {
  url: string;
  scanDate: string;
  positives: number;
  total: number;
  permalink: string;
  scans: Record<string, ScanResult>;
}
```

### Internal Scanner API

#### VulnerabilityScanner Class

```typescript
const scanner = new VulnerabilityScanner();
const result = await scanner.scanWebApplication({ url });
```

#### Scan Output

```typescript
interface ScanResult {
  vulnerabilities: Vulnerability[];
  executiveSummary: string;
}
```

---

## Configuration

### Environment Variables

```bash
# Required
VIRUSTOTAL_API_KEY=your_api_key_here

# Optional
NEXT_PUBLIC_APP_URL=http://localhost:9002
```

### VirusTotal Rate Limits

- **Free Tier**: 4 requests/minute, 1000 requests/day
- **Premium Tier**: Higher limits available

### Rate Limiting Strategy

The application implements intelligent rate limiting:
- Exponential backoff for failed requests
- Request queuing for bulk operations
- Caching of recent scan results

---

## Troubleshooting

### Common Issues

#### API Key Problems

**Error**: "VIRUSTOTAL_API_KEY environment variable is not set"

**Solution**:
1. Check that `.env.local` exists
2. Verify API key is correctly formatted
3. Restart the development server

**Error**: "VirusTotal API rate limit exceeded"

**Solution**:
1. Wait for rate limit to reset
2. Consider upgrading to premium API
3. Implement request queuing

#### Scanning Issues

**Error**: "Invalid URL format"

**Solution**:
1. Ensure URL includes protocol (http:// or https://)
2. Check for typos in the URL
3. Verify the domain exists

**Error**: "Scan timeout"

**Solution**:
1. Check internet connection
2. Verify VirusTotal service status
3. Try scanning again after a delay

#### Development Issues

**Error**: "Build failed"

**Solution**:
1. Run `npm install` to update dependencies
2. Check TypeScript types: `npm run typecheck`
3. Clear Next.js cache: `rm -rf .next`

### Debug Mode

Enable debug logging by setting:

```bash
# In .env.local
DEBUG=threatlens:*
```

### Getting Help

- **GitHub Issues**: Report bugs and feature requests
- **Discussions**: Community support and questions
- **Documentation**: Check this docs folder first

---

## Development

### Project Structure

See the main [README](../README.md#-project-structure) for detailed structure.

### Adding New Vulnerability Types

1. **Update Scanner Logic** in `src/lib/scanner.ts`
2. **Add Type Definitions** if needed
3. **Update Tests** (when available)
4. **Update Documentation**

### Code Style

- **TypeScript**: Strict mode enabled
- **ESLint**: Follow recommended rules
- **Prettier**: Consistent formatting (when configured)
- **Components**: Functional components with hooks

---

## Security Considerations

### Data Privacy

- **No Data Storage**: Scans are performed in real-time
- **API Keys**: Never exposed to client-side code
- **URL Privacy**: Only sent to VirusTotal for analysis

### API Security

- **Rate Limiting**: Prevents abuse
- **Input Validation**: All URLs validated
- **Error Handling**: No sensitive information leaked

---

## Performance

### Optimization Strategies

- **Caching**: Recent scan results cached
- **Lazy Loading**: Components loaded on demand
- **Bundle Size**: Optimized for fast loading
- **Turbopack**: Fast development builds

### Monitoring

- **Scan Performance**: Track scan durations
- **API Usage**: Monitor rate limits
- **Error Rates**: Track failed scans

---

## License

See the [LICENSE](../LICENSE) file for details.