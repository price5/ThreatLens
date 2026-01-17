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
import { QRUploadForm } from '@/components/threatlens/qr-upload-form';
import { useToast } from '@/hooks/use-toast';
import { Progress } from '@/components/ui/progress';

const formSchema = z.object({
  url: z.string().url(),
});

export default function Home() {
  // 🔹 TAB STATE
  const [activeTab, setActiveTab] = useState<'link' | 'qr'>('link');

  // 🔹 SCAN STATES
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [scanData, setScanData] = useState<ScanResult | null>(null);
  const [scanUrl, setScanUrl] = useState('');
  const [selectedVulnerability, setSelectedVulnerability] =
    useState<Vulnerability | null>(null);

  const { toast } = useToast();

  // 🔹 HANDLE URL SCAN (USED BY BOTH LINK & QR)
  const handleScan = async (data: z.infer<typeof formSchema>) => {
    setIsLoading(true);
    setScanData(null);
    setScanUrl(data.url);
    setProgress(0);

    const progressInterval = setInterval(() => {
      setProgress((prev) => {
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
    } catch (error) {
      clearInterval(progressInterval);
      console.error(error);
      toast({
        variant: 'destructive',
        title: 'Scan Failed',
        description:
          'An error occurred while scanning the URL. Please try again.',
      });
      setScanData(null);
      setProgress(0);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center min-h-screen p-4 md:p-8 bg-background">
      {/* HEADER */}
      <header className="w-full max-w-6xl mb-12">
        <Logo />
      </header>

      {/* MAIN */}
      <main className="w-full max-w-6xl flex-grow">
        <div className="flex flex-col items-center justify-center">

          {/* 🔹 TABS */}
          <div className="flex justify-center mb-8">
            <div className="flex border border-border rounded-lg overflow-hidden">
              <button
                onClick={() => setActiveTab('link')}
                className={`px-6 py-2 text-sm font-medium transition ${
                  activeTab === 'link'
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-background text-muted-foreground hover:bg-muted'
                }`}
              >
                Link
              </button>

              <button
                onClick={() => setActiveTab('qr')}
                className={`px-6 py-2 text-sm font-medium transition ${
                  activeTab === 'qr'
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-background text-muted-foreground hover:bg-muted'
                }`}
              >
                QR Code
              </button>
            </div>
          </div>

          {/* 🔹 FORMS */}
          <section className="w-full mb-16">
            {activeTab === 'link' && (
              <ScanForm onSubmit={handleScan} isLoading={isLoading} />
            )}

            {activeTab === 'qr' && (
              <QRUploadForm
                onDecodedUrl={(url) => {
                  handleScan({ url });
                  setActiveTab('link');
                }}
              />
            )}
          </section>

          {/* 🔹 LOADING */}
          {isLoading && (
            <section className="w-full max-w-2xl text-center">
              <Progress value={progress} className="w-full mb-4" />
              <p className="text-muted-foreground animate-pulse">
                Scanning {scanUrl}... this may take a moment.
              </p>
            </section>
          )}

          {/* 🔹 REPORT */}
          {scanData && (
            <section className="w-full animate-in fade-in duration-500">
              <ScanReport
                data={scanData}
                url={scanUrl}
                onSelectVulnerability={setSelectedVulnerability}
              />
            </section>
          )}
        </div>
      </main>

      {/* 🔹 VULNERABILITY DETAILS */}
      <VulnerabilityDetails
        vulnerability={selectedVulnerability}
        onOpenChange={(open) => !open && setSelectedVulnerability(null)}
      />
    </div>
  );
}
