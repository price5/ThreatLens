// The logo component for the ThreatLens application.
import { ShieldCheck } from 'lucide-react';

export function Logo({ className }: { className?: string }) {
  return (
    <div className={`inline-flex items-center gap-3 ${className}`}>
      <ShieldCheck className="h-8 w-8 text-accent" />
      <span className="text-2xl font-bold text-foreground tracking-wide">
        Threat<span className="text-accent">Lens</span>
      </span>
    </div>
  );
}
