// Defines server-side actions for the application.
"use server";

import { VulnerabilityScanner, ScanInput, ScanResult } from "@/lib/scanner";

export async function performScan(data: ScanInput): Promise<ScanResult> {
  try {
    const scanner = new VulnerabilityScanner();

    // Add a delay to simulate a comprehensive scan for better UX with the progress bar.
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // Perform the vulnerability scan
    const result = await scanner.scanWebApplication(data);

    return result;
  } catch (error) {
    console.error("Error performing scan:", error);
    throw new Error(
      "The security scan failed. Please check the application URL and try again.",
    );
  }
}
