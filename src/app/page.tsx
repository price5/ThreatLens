// The main page component for the application.
'use client';
import { useState } from 'react';
import { z } from 'zod';
import { performScan } from '@/app/actions';
import type { ScanResult, Vulnerability } from '@/lib/types';
import { Logo } from '@/components/threatlens/logo';
import { ScanForm } from '@/components/threatlens/scan-form';
import { ScanReport } from '@/components/threatlens/scan-report';
import { VulnerabilityDetails } from '@/components/threatlens/vulnerability-details';
import { useToast } from "@/hooks/use-toast";
import { Progress } from "@/components/ui/progress";

const formSchema = z.object({
  url: z.string().url(),
});

export default function Home() {
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [scanData, setScanData] = useState<ScanResult | null>(null);
  const [scanUrl, setScanUrl] = useState('');
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);
  const { toast } = useToast();

  const handleScan = async (data: z.infer<typeof formSchema>) => {
    setIsLoading(true);
    setScanData(null);
    setScanUrl(data.url);
    setProgress(0);

    const progressInterval = setInterval(() => {
        setProgress(prev => {
            if (prev >= 95) {
                clearInterval(progressInterval);
                return 95;
            }
            return prev + 5;
        });
    }, 150);

    try {
      const result = await performScan(data);
      clearInterval(progressInterval);
      setProgress(100);
      setScanData(result);
    } catch (e) {
      clearInterval(progressInterval);
      console.error(e);
      toast({
        variant: "destructive",
        title: "Scan Failed",
        description: "An error occurred while scanning the URL. Please try again.",
      });
      setScanData(null);
      setProgress(0);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center min-h-screen p-4 md:p-8 bg-background">
      <header className="w-full max-w-6xl mb-12">
        <Logo />
      </header>
      <main className="w-full max-w-6xl flex-grow">
        <div className="flex flex-col items-center justify-center">
            <section className="w-full mb-16">
                <ScanForm onSubmit={handleScan} isLoading={isLoading} />
            </section>

            {isLoading && (
                <section className="w-full max-w-2xl text-center">
                    <Progress value={progress} className="w-full mb-4" />
                    <p className="text-muted-foreground animate-pulse">Scanning {scanUrl}... this may take a moment.</p>
                </section>
            )}

            {scanData && (
                <section className="w-full animate-in fade-in duration-500">
                    <ScanReport data={scanData} url={scanUrl} onSelectVulnerability={setSelectedVulnerability} />
                </section>
            )}
        </div>
      </main>
      <VulnerabilityDetails 
        vulnerability={selectedVulnerability}
        onOpenChange={(open) => !open && setSelectedVulnerability(null)}
      />
    </div>
  );
}
