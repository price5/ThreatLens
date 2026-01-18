// The component for displaying the results of a vulnerability scan.
'use client';

import type { ScanResult, Vulnerability } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { AlertTriangle, ShieldAlert, ShieldCheck, Download } from 'lucide-react';
import React from 'react';
import { VirusTotalResults } from './virus-total-results';

type ScanReportProps = {
  data: ScanResult;
  url: string;
  onSelectVulnerability: (vulnerability: Vulnerability) => void;
};

const severityIcons: Record<Vulnerability['severity'], React.ReactNode> = {
  High: <AlertTriangle className="h-4 w-4 text-destructive" />,
  Medium: <ShieldAlert className="h-4 w-4 text-chart-4" />,
  Low: <ShieldCheck className="h-4 w-4 text-chart-2" />,
};

const severityBadgeVariants: Record<Vulnerability['severity'], 'destructive' | 'secondary' | 'outline'> = {
    High: 'destructive',
    Medium: 'secondary',
    Low: 'outline',
};

export function ScanReport({ data, url, onSelectVulnerability }: ScanReportProps) {
    const counts = React.useMemo(() => {
        return data.vulnerabilities.reduce(
            (acc: Record<Vulnerability['severity'], number>, v: Vulnerability) => {
                acc[v.severity] = (acc[v.severity] || 0) + 1;
                return acc;
            },
            { High: 0, Medium: 0, Low: 0 }
        );
    }, [data.vulnerabilities]);

    const handleDownload = () => {
        let report = `# ThreatLens Vulnerability Report for ${url}\n\n`;
        report += `## Executive Summary\n\n${data.executiveSummary}\n\n`;
        report += '---\n\n';
        report += `## Vulnerabilities Found\n\n`;
        report += `*   **High:** ${counts.High}\n`;
        report += `*   **Medium:** ${counts.Medium}\n`;
        report += `*   **Low:** ${counts.Low}\n\n`;

        data.vulnerabilities.forEach((v: Vulnerability) => {
            report += `### ${v.type} (${v.severity} Severity)\n\n`;
            report += `**Description:**\n${v.description}\n\n`;
            report += `**Potential Impact:**\n${v.potentialImpact}\n\n`;
            report += `**Remediation:**\n${v.remediation}\n\n`;
            report += '---\n\n';
        });

        const blob = new Blob([report], { type: 'text/markdown' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        const hostname = new URL(url).hostname.replace(/\./g, '_');
        link.download = `threatlens-report-${hostname}.md`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    return (
        <div className="space-y-8">
            <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4">
                <h2 className="text-3xl font-bold">Scan Report for <span className="text-accent break-all">{url}</span></h2>
                <Button onClick={handleDownload} variant="outline" className="shrink-0">
                    <Download className="mr-2 h-4 w-4" />
                    Download Report
                </Button>
            </div>
            
            <div className="grid gap-4 md:grid-cols-3">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">High Severity</CardTitle>
                        {severityIcons.High}
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold text-destructive">{counts.High}</div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Medium Severity</CardTitle>
                        {severityIcons.Medium}
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold text-chart-4">{counts.Medium}</div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Low Severity</CardTitle>
                        {severityIcons.Low}
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold text-chart-2">{counts.Low}</div>
                    </CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Executive Summary</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="text-muted-foreground whitespace-pre-line">
                        {data.executiveSummary}
                    </div>
                </CardContent>
            </Card>

            {/* Enhanced VirusTotal Results */}
            {data.virusTotalAnalysis && (
                <VirusTotalResults results={data.virusTotalAnalysis} />
            )}

            <Card>
                <CardHeader>
                    <CardTitle>Vulnerabilities Details</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="border rounded-md">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead className="w-[200px]">Type</TableHead>
                                    <TableHead className="w-[150px]">Severity</TableHead>
                                    <TableHead>Description</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {data.vulnerabilities.map((v: Vulnerability, index: number) => (
                                    <TableRow 
                                        key={index}
                                        onClick={() => onSelectVulnerability(v)}
                                        className="cursor-pointer"
                                    >
                                        <TableCell className="font-medium">{v.type}</TableCell>
                                        <TableCell>
                                            <Badge variant={severityBadgeVariants[v.severity as keyof typeof severityBadgeVariants]} className="capitalize">
                                                <div className="flex items-center gap-2">
                                                    {severityIcons[v.severity]}
                                                    <span>{v.severity}</span>
                                                </div>
                                            </Badge>
                                        </TableCell>
                                        <TableCell>
                                            <p className="line-clamp-2">{v.description}</p>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
