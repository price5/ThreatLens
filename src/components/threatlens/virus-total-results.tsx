// Enhanced VirusTotal Results Display Component
'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, CheckCircle, XCircle, Clock, Server } from 'lucide-react';
import { VirusTotalUrlReport, VirusTotalAnalysisResult } from '@/lib/virustotal';

interface VirusTotalResultsProps {
  results: VirusTotalUrlReport | VirusTotalAnalysisResult | null;
}

export function VirusTotalResults({ results }: VirusTotalResultsProps) {
  if (!results) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            VirusTotal Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">No VirusTotal analysis available.</p>
        </CardContent>
      </Card>
    );
  }

  // Handle different response formats
  const isV3Format = 'data' in results;
  const stats = isV3Format 
    ? (results as VirusTotalAnalysisResult).data.attributes.stats
    : {
        malicious: (results as VirusTotalUrlReport).positives,
        harmless: (results as VirusTotalUrlReport).total - (results as VirusTotalUrlReport).positives,
        suspicious: 0,
        undetected: 0,
        timeout: 0,
        failure: 0,
        'type-unsupported': 0,
        'confirmed-timeout': 0
      };

  const totalEngines = Object.values(stats).reduce((sum, count) => sum + count, 0);
  const maliciousCount = stats.malicious;
  const suspiciousCount = stats.suspicious;
  const harmlessCount = stats.harmless;
  const undetectedCount = stats.undetected;

  const threatLevel = maliciousCount > 0 ? 'high' : suspiciousCount > 0 ? 'medium' : 'low';
  const threatPercentage = totalEngines > 0 ? ((maliciousCount + suspiciousCount) / totalEngines) * 100 : 0;

  const getThreatIcon = () => {
    switch (threatLevel) {
      case 'high':
        return <XCircle className="h-6 w-6 text-red-500" />;
      case 'medium':
        return <AlertTriangle className="h-6 w-6 text-yellow-500" />;
      default:
        return <CheckCircle className="h-6 w-6 text-green-500" />;
    }
  };

  const getThreatColor = () => {
    switch (threatLevel) {
      case 'high':
        return 'text-red-500';
      case 'medium':
        return 'text-yellow-500';
      default:
        return 'text-green-500';
    }
  };

  const getThreatBadgeVariant = () => {
    switch (threatLevel) {
      case 'high':
        return 'destructive';
      case 'medium':
        return 'secondary';
      default:
        return 'default';
    }
  };

  return (
    <div className="space-y-6">
      {/* Overall Threat Assessment */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            VirusTotal Analysis
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {getThreatIcon()}
              <div>
                <p className="font-semibold">Threat Level: <span className={getThreatColor()}>{threatLevel.toUpperCase()}</span></p>
                <p className="text-sm text-muted-foreground">
                  {maliciousCount}/{totalEngines} security engines detected threats
                </p>
              </div>
            </div>
            <Badge variant={getThreatBadgeVariant()} className="capitalize">
              {threatPercentage.toFixed(1)}% Risk
            </Badge>
          </div>
          
          {/* Threat Progress Bar */}
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Threat Detection Rate</span>
              <span>{threatPercentage.toFixed(1)}%</span>
            </div>
            <Progress 
              value={threatPercentage} 
              className="h-2"
            />
          </div>
        </CardContent>
      </Card>

      {/* Detailed Statistics */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Engine Detection Results
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-3 bg-red-50 rounded-lg border border-red-200">
              <XCircle className="h-6 w-6 text-red-500 mx-auto mb-1" />
              <p className="font-bold text-red-600">{maliciousCount}</p>
              <p className="text-xs text-red-600">Malicious</p>
            </div>
            <div className="text-center p-3 bg-yellow-50 rounded-lg border border-yellow-200">
              <AlertTriangle className="h-6 w-6 text-yellow-500 mx-auto mb-1" />
              <p className="font-bold text-yellow-600">{suspiciousCount}</p>
              <p className="text-xs text-yellow-600">Suspicious</p>
            </div>
            <div className="text-center p-3 bg-green-50 rounded-lg border border-green-200">
              <CheckCircle className="h-6 w-6 text-green-500 mx-auto mb-1" />
              <p className="font-bold text-green-600">{harmlessCount}</p>
              <p className="text-xs text-green-600">Harmless</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg border border-gray-200">
              <Clock className="h-6 w-6 text-gray-500 mx-auto mb-1" />
              <p className="font-bold text-gray-600">{undetectedCount}</p>
              <p className="text-xs text-gray-600">Undetected</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Individual Engine Results (for v3 format) */}
      {isV3Format && (results as VirusTotalAnalysisResult).data.attributes.results && (
        <Card>
          <CardHeader>
            <CardTitle>Security Engine Results</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {Object.entries((results as VirusTotalAnalysisResult).data.attributes.results).map(([engineName, result]) => (
                <div key={engineName} className="flex items-center justify-between p-2 rounded-lg border">
                  <div className="flex items-center gap-2">
                    {result.category === 'malicious' && <XCircle className="h-4 w-4 text-red-500" />}
                    {result.category === 'suspicious' && <AlertTriangle className="h-4 w-4 text-yellow-500" />}
                    {result.category === 'harmless' && <CheckCircle className="h-4 w-4 text-green-500" />}
                    {result.category === 'undetected' && <Clock className="h-4 w-4 text-gray-500" />}
                    <span className="font-medium">{engineName}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={
                      result.category === 'malicious' ? 'destructive' :
                      result.category === 'suspicious' ? 'secondary' :
                      result.category === 'harmless' ? 'default' : 'outline'
                    } className="capitalize">
                      {result.category}
                    </Badge>
                    {result.result && (
                      <span className="text-xs text-muted-foreground max-w-xs truncate">
                        {result.result}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan Information */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Total Security Engines:</span>
            <span className="font-medium">{totalEngines}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Scan Date:</span>
            <span className="font-medium">
              {isV3Format 
                ? new Date((results as VirusTotalAnalysisResult).data.attributes.date * 1000).toLocaleString()
                : (results as VirusTotalUrlReport).scanDate
              }
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Status:</span>
            <Badge variant="outline" className="capitalize">
              {isV3Format ? (results as VirusTotalAnalysisResult).data.attributes.status : 'Completed'}
            </Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}