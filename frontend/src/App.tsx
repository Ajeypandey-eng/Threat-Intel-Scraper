import React, { useState } from 'react';
import { ThemeToggleButton } from './components/Skiper26';
import { SmoothInput } from './components/Skiper106';
import { Footer } from './components/Footer';
import { motion, AnimatePresence } from 'framer-motion';

type ScanResult = {
  domain: string;
  score: number;
  verdict: string;
  deductions: number;
  warnings: string[];
  positives: string[];
  data: {
    whois: Record<string, any>;
    dns: Record<string, any>;
    tls: Record<string, any>;
    headers: Record<string, any>;
  };
};

const ScoreArc = ({ score }: { score: number }) => {
  const radius = 54;
  const circumference = Math.PI * radius; // half circle
  const color = score >= 85 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="140" height="80" viewBox="0 0 140 80">
        {/* Background track */}
        <path
          d="M 10 70 A 60 60 0 0 1 130 70"
          fill="none"
          stroke="var(--muted2)"
          strokeWidth="10"
          strokeLinecap="round"
        />
        {/* Progress arc */}
        <path
          d="M 10 70 A 60 60 0 0 1 130 70"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * circumference} ${circumference}`}
          style={{ transition: 'stroke-dasharray 1s ease' }}
        />
        <text x="70" y="65" textAnchor="middle" fontSize="26" fontWeight="900" fill="var(--foreground)">
          {score}
        </text>
        <text x="70" y="78" textAnchor="middle" fontSize="10" fill="var(--foreground)" opacity="0.5">
          TRUST SCORE
        </text>
      </svg>
    </div>
  );
};

const verdictColor = (verdict: string) => {
  if (verdict === 'Trusted') return 'text-green-500';
  if (verdict === 'Low Risk') return 'text-yellow-500';
  if (verdict === 'Moderate Risk') return 'text-orange-500';
  return 'text-red-500';
};

const DataCard = ({ title, data }: { title: string; data: Record<string, any> }) => {
  const [open, setOpen] = useState(false);
  const entries = Object.entries(data).filter(([k]) => k !== 'error');
  const hasError = data?.error;

  return (
    <div className="border border-foreground/10 rounded-2xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between p-4 hover:bg-foreground/5 transition-colors"
      >
        <span className="font-bold uppercase tracking-wider text-sm">{title}</span>
        <span className="opacity-40 text-xs">{open ? '▲ collapse' : '▼ expand'}</span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden"
          >
            <div className="p-4 border-t border-foreground/10 space-y-2">
              {hasError && (
                <p className="text-red-400 text-xs font-mono">Error: {hasError}</p>
              )}
              {entries.map(([key, value]) => (
                <div key={key} className="flex gap-3 text-xs">
                  <span className="opacity-40 w-40 shrink-0 font-mono">{key}</span>
                  <span className="opacity-80 font-mono break-all">
                    {Array.isArray(value)
                      ? value.length > 0 ? value.join(', ') : '—'
                      : value != null ? String(value) : '—'}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

function App() {
  const [domain, setDomain] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;

    setLoading(true);
    setError('');
    setResult(null);

    const apiBaseUrl = import.meta.env.VITE_API_URL || '/api';

    try {
      const response = await fetch(`${apiBaseUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      });

      const data = await response.json();
      if (response.ok) {
        setResult(data);
      } else {
        setError(data.error || 'Failed to scan domain.');
      }
    } catch {
      setError('Cannot connect to server. Make sure the Flask backend is running.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col" style={{ backgroundColor: 'var(--background)', color: 'var(--foreground)' }}>
      {/* Header */}
      <header className="px-6 py-4 flex items-center justify-between border-b" style={{ borderColor: 'color-mix(in srgb, var(--foreground) 10%, transparent)' }}>
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="font-black uppercase tracking-widest text-sm">Threat Intel</span>
        </div>
        <ThemeToggleButton variant="circle" start="top-right" />
      </header>

      {/* Hero */}
      <main className="flex-1 flex flex-col items-center px-6 py-16 gap-12">
        <div className="text-center space-y-4 max-w-2xl">
          <h1 className="text-6xl md:text-7xl font-black uppercase tracking-tighter leading-none">
            Infrastructure
            <br />
            <span style={{ opacity: 0.3 }}>Risk Scanner</span>
          </h1>
          <p className="text-sm" style={{ opacity: 0.5 }}>
            Analyzes domain age, DNS security records, TLS certificates, and HTTP headers to compute a trust score.
          </p>
        </div>

        {/* Scan Form */}
        <form onSubmit={handleScan} className="w-full max-w-lg flex flex-col items-center gap-4">
          <SmoothInput
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            wrapperClassName="w-full max-w-lg"
          />
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="w-full py-3 rounded-2xl font-bold uppercase tracking-widest text-sm transition-all active:scale-95 disabled:opacity-40"
            style={{ backgroundColor: 'var(--foreground)', color: 'var(--background)' }}
          >
            {loading ? (
              <span className="inline-flex items-center gap-2">
                <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeDasharray="31.4" strokeDashoffset="10" />
                </svg>
                Scanning...
              </span>
            ) : (
              'Scan Domain'
            )}
          </button>
        </form>

        {error && (
          <div className="max-w-lg w-full p-4 border border-red-500/30 rounded-xl bg-red-500/10 text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Results */}
        <AnimatePresence>
          {result && (
            <motion.div
              key={result.domain}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
              className="w-full max-w-2xl space-y-6"
            >
              {/* Score Card */}
              <div
                className="p-8 rounded-3xl border flex flex-col items-center gap-4 text-center"
                style={{ borderColor: 'color-mix(in srgb, var(--foreground) 10%, transparent)', backgroundColor: 'var(--muted)' }}
              >
                <p className="text-xs uppercase tracking-widest opacity-40 font-bold">{result.domain}</p>
                <ScoreArc score={result.score} />
                <p className={`text-2xl font-black uppercase tracking-tight ${verdictColor(result.verdict)}`}>
                  {result.verdict}
                </p>
                <p className="text-xs opacity-40 max-w-xs">
                  Score is based on domain age, DNS email security (SPF/DMARC), TLS validity, and HTTP security headers.
                  Higher score = more trustworthy.
                </p>
              </div>

              {/* Positives */}
              {result.positives?.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs uppercase tracking-widest opacity-40 font-bold">What looks good</h3>
                  <ul className="space-y-1">
                    {result.positives.map((p, i) => (
                      <li key={i} className="text-sm text-green-500 flex gap-2 items-start">
                        <span>{p}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Warnings */}
              {result.warnings?.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs uppercase tracking-widest opacity-40 font-bold">Issues found</h3>
                  <ul className="space-y-2">
                    {result.warnings.map((w, i) => (
                      <li key={i} className="text-sm text-orange-400 flex gap-2 items-start p-3 rounded-xl" style={{ backgroundColor: 'color-mix(in srgb, var(--foreground) 4%, transparent)' }}>
                        <span className="shrink-0">⚠</span>
                        <span>{w.replace('⚠ ', '')}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Raw Data Accordion */}
              <div className="space-y-3">
                <h3 className="text-xs uppercase tracking-widest opacity-40 font-bold">Raw Telemetry</h3>
                <DataCard title="WHOIS" data={result.data.whois} />
                <DataCard title="DNS Records" data={result.data.dns} />
                <DataCard title="TLS Certificate" data={result.data.tls} />
                <DataCard title="HTTP Security Headers" data={result.data.headers.headers ?? {}} />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Smooth gradient divider into footer */}
      <div className="relative h-32 pointer-events-none" aria-hidden>
        <div
          className="absolute inset-0"
          style={{
            background: 'linear-gradient(to bottom, transparent, color-mix(in srgb, var(--foreground) 4%, transparent))',
          }}
        />
        <motion.div
          initial={{ scaleX: 0 }}
          whileInView={{ scaleX: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1] }}
          className="absolute bottom-0 left-0 right-0 h-px origin-left"
          style={{ backgroundColor: 'color-mix(in srgb, var(--foreground) 15%, transparent)' }}
        />
      </div>

      <Footer />
    </div>
  );
}

export default App;
