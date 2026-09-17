import React, { useState } from 'react';
import { ThemeToggleButton } from './components/Skiper26';
import { SmoothInput } from './components/Skiper106';
import { Footer } from './components/Footer';
import { CaptchaPuzzle } from './components/CaptchaPuzzle';
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
  ai?: {
    composite_ai_risk_score: number;
    composite_verdict: string;
    lexical?: {
      risk_score: number;
      malicious_probability: number;
      verdict: string;
      confidence: number;
      entropy: number;
      is_ip_address: boolean;
      obfuscation_detected: boolean;
      latency_ms: number;
    };
    network_ml?: {
      risk_score: number;
      malicious_probability: number;
      verdict: string;
    };
    anomaly?: {
      anomaly_score: number;
      is_anomaly: boolean;
      anomaly_level: string;
      zero_day_suspect: boolean;
    };
  };
  analyst_report?: {
    threat_level: string;
    executive_summary: string;
    technical_evidence: string[];
    mitre_attack_mappings: Array<{
      technique_id: string;
      name: string;
      tactics: string[];
      description: string;
    }>;
    actionable_recommendations: string[];
  };
  smuggling?: {
    is_concatenated: boolean;
    is_multi_protocol?: boolean;
    technique?: string;
    schemes_found?: string[];
    lure_prefix_raw?: string;
    lure_prefix_domain?: string;
    active_payload_raw?: string;
    active_payload_domain?: string;
    immunity_tier?: string;
    broadcast_alert?: string;
    warning?: string;
  };
  lure_prefix_domain?: string;
  active_payload_domain?: string;
};

const ScoreArc = ({ score }: { score: number }) => {
  const radius = 60;
  const circumference = Math.PI * radius;
  const boundedScore = Math.min(100, Math.max(0, score));
  const color = boundedScore >= 85 ? '#22c55e' : boundedScore >= 60 ? '#eab308' : boundedScore >= 40 ? '#f97316' : '#ef4444';

  return (
    <div className="flex flex-col items-center gap-3 w-full max-w-[220px] sm:max-w-[260px]">
      <div className="relative w-full">
        <svg viewBox="0 0 140 80" className="w-full h-auto">
          {/* Background track */}
          <path
            d="M 10 70 A 60 60 0 0 1 130 70"
            fill="none"
            stroke="var(--muted2)"
            strokeWidth="10"
            strokeLinecap="round"
          />
          {/* Progress arc */}
          <motion.path
            d="M 10 70 A 60 60 0 0 1 130 70"
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: circumference * (1 - boundedScore / 100) }}
            transition={{ duration: 1, ease: 'easeOut' }}
          />
          <text x="70" y="65" textAnchor="middle" fontSize="22" fontWeight="900" fill="var(--foreground)">
            {score}
          </text>
          <text x="70" y="78" textAnchor="middle" fontSize="8" fontWeight="700" letterSpacing="0.05em" fill="var(--foreground)" opacity="0.5">
            HEURISTIC TRUST
          </text>
        </svg>
      </div>
    </div>
  );
};

const verdictColor = (verdict: string) => {
  if (verdict === 'Trusted' || verdict === 'Benign') return 'text-green-500';
  if (verdict === 'Low Risk') return 'text-yellow-500';
  if (verdict === 'Moderate Risk') return 'text-orange-500';
  return 'text-red-500';
};

const threatBadgeColor = (level: string) => {
  if (level === 'CRITICAL') return 'bg-red-500/20 text-red-400 border-red-500/40';
  if (level === 'ELEVATED') return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
  return 'bg-green-500/20 text-green-400 border-green-500/40';
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

  // Community Threat Reporting State
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [humanVerified, setHumanVerified] = useState(false);
  const [submittingReport, setSubmittingReport] = useState(false);
  const [reportSuccess, setReportSuccess] = useState<any>(null);
  const [reportError, setReportError] = useState('');

  const handleReportThreat = async () => {
    if (!result || !humanVerified) return;
    setSubmittingReport(true);
    setReportError('');

    const apiBaseUrl = import.meta.env.VITE_API_URL || '/api';
    const targetDomain = result.active_payload_domain || result.domain;
    const lurePrefix = result.lure_prefix_domain || result.smuggling?.lure_prefix_domain || '';

    try {
      const resp = await fetch(`${apiBaseUrl}/report-threat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: targetDomain,
          lure_prefix: lurePrefix,
          risk_score: result.ai?.composite_ai_risk_score ?? (100 - result.score),
          threat_level: result.analyst_report?.threat_level || 'ELEVATED',
          human_verified: true,
        }),
      });

      let data: any = {};
      try {
        data = await resp.json();
      } catch {
        const text = await resp.text().catch(() => '');
        data = { error: text || `Server error (${resp.status})` };
      }

      if (resp.ok) {
        setReportSuccess(data);
      } else {
        setReportError(data.error || `Failed to submit threat report (${resp.status}).`);
      }
    } catch (err: any) {
      setReportError(err?.message || 'Network error: unable to connect to threat reporting service.');
    } finally {
      setSubmittingReport(false);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;

    setLoading(true);
    setError('');
    setResult(null);
    setReportSuccess(null);
    setReportError('');
    setHumanVerified(false);

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
      setError('Cannot connect to server. Make sure the Flask backend is running on http://127.0.0.1:5000');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col" style={{ backgroundColor: 'var(--background)', color: 'var(--foreground)' }}>
      {/* Header */}
      <header className="px-4 sm:px-6 lg:px-10 py-4 flex items-center justify-between border-b" style={{ borderColor: 'color-mix(in srgb, var(--foreground) 10%, transparent)' }}>
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="font-black uppercase tracking-widest text-sm">Threat Intel Scraper</span>
        </div>
        <ThemeToggleButton variant="circle" start="top-right" />
      </header>

      {/* Hero */}
      <main className="flex-1 flex flex-col items-center px-4 sm:px-6 lg:px-10 py-12 sm:py-16 gap-10">
        <div className="text-center space-y-4 max-w-2xl sm:max-w-3xl">
          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-black uppercase tracking-tighter leading-tight">
            Autonomous
            <br />
            <span className="block mt-2 text-4xl sm:text-5xl md:text-6xl lg:text-7xl bg-gradient-to-r from-indigo-400 via-cyan-400 to-emerald-400 bg-clip-text text-transparent">
              Threat Intelligence
            </span>
          </h1>
          <p className="text-sm sm:text-base leading-relaxed text-slate-400 max-w-xl mx-auto">
            Real-time security scanner analyzing domain authentication, server infrastructure, certificate validity, and URL deception patterns.
          </p>
        </div>

        {/* Scan Form */}
        <form onSubmit={handleScan} className="w-full max-w-lg flex flex-col items-center gap-4">
          <SmoothInput
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com or https://suspicious-site.xyz/login"
            wrapperClassName="w-full max-w-lg"
          />
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="w-full py-3.5 rounded-2xl font-bold uppercase tracking-widest text-sm transition-all active:scale-95 disabled:opacity-40 shadow-lg shadow-indigo-500/10 hover:shadow-indigo-500/20"
            style={{ backgroundColor: 'var(--foreground)', color: 'var(--background)' }}
          >
            {loading ? (
              <span className="inline-flex items-center gap-2">
                <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeDasharray="31.4" strokeDashoffset="10" />
                </svg>
                Analyzing Threat Signals...
              </span>
            ) : (
              'Scan Threat Profile'
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
              className="w-full max-w-3xl space-y-8"
            >
              {/* Adversarial Concatenated URL Smuggling & Multi-Protocol Warning Banner */}
              {result.smuggling?.is_concatenated && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.98 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="p-6 rounded-3xl border space-y-4 text-left shadow-sm transition-colors"
                  style={{
                    backgroundColor: 'var(--muted)',
                    borderColor: 'color-mix(in srgb, var(--foreground) 15%, transparent)',
                  }}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2.5">
                    <div className="flex items-center gap-2.5 text-xs uppercase tracking-widest font-black" style={{ color: 'var(--foreground)' }}>
                      <span className="relative flex h-2.5 w-2.5">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                      </span>
                      <span>Threat Intel Broadcast: Protocol Chaining & Smuggling Detected</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      {result.smuggling.schemes_found && result.smuggling.schemes_found.length > 0 && (
                        <span
                          className="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider border"
                          style={{
                            backgroundColor: 'color-mix(in srgb, var(--foreground) 6%, transparent)',
                            borderColor: 'color-mix(in srgb, var(--foreground) 15%, transparent)',
                            color: 'var(--foreground)',
                          }}
                        >
                          {result.smuggling.schemes_found.join(' + ').toUpperCase()}
                        </span>
                      )}
                      <span
                        className="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider border"
                        style={{
                          backgroundColor: 'color-mix(in srgb, var(--foreground) 6%, transparent)',
                          borderColor: 'color-mix(in srgb, var(--foreground) 15%, transparent)',
                          color: 'var(--foreground)',
                        }}
                      >
                        {result.smuggling.technique || 'Concatenated Schemes'}
                      </span>
                    </div>
                  </div>

                  <p
                    className="text-xs leading-relaxed"
                    style={{ color: 'color-mix(in srgb, var(--foreground) 75%, transparent)' }}
                  >
                    Multiple protocol schemes or chained domain markers detected in the input (e.g., HTTP, FTP, HTTPS, FTPS). 
                    Attackers exploit this technique to bypass filters and maliciously frame innocent minor domains (local businesses, schools, blogs) or major backbones to defame them on public threat blocklists. 
                    Our intelligence engine has applied <strong style={{ color: 'var(--foreground)' }}>Universal Framing Immunity</strong> to shield the innocent lure domain from reputation damage, and quarantined the active payload for inspection.
                  </p>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono pt-1">
                    {/* Card 1: Shielded Lure */}
                    <div
                      className="p-3.5 rounded-2xl border flex flex-col justify-between gap-2"
                      style={{
                        backgroundColor: 'color-mix(in srgb, var(--foreground) 4%, transparent)',
                        borderColor: 'color-mix(in srgb, var(--foreground) 10%, transparent)',
                      }}
                    >
                      <div className="flex items-center justify-between text-[10px] uppercase font-bold opacity-60">
                        <div className="flex items-center gap-1.5">
                          <svg className="w-3.5 h-3.5 text-emerald-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                          </svg>
                          <span>Shielded Lure</span>
                        </div>
                        <span className="text-[9px] bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded font-bold">
                          Immunity Active
                        </span>
                      </div>
                      <span className="font-bold text-sm truncate" style={{ color: 'var(--foreground)' }} title={result.lure_prefix_domain || result.smuggling.lure_prefix_domain}>
                        {result.lure_prefix_domain || result.smuggling.lure_prefix_domain}
                      </span>
                      <span className="text-[10px] text-emerald-600/90 dark:text-emerald-400/80 font-sans">
                        Minor & Major Domain Shield
                      </span>
                    </div>

                    {/* Card 2: Chained Protocols */}
                    <div
                      className="p-3.5 rounded-2xl border flex flex-col justify-between gap-2"
                      style={{
                        backgroundColor: 'color-mix(in srgb, var(--foreground) 4%, transparent)',
                        borderColor: 'color-mix(in srgb, var(--foreground) 10%, transparent)',
                      }}
                    >
                      <div className="flex items-center justify-between text-[10px] uppercase font-bold opacity-60">
                        <div className="flex items-center gap-1.5">
                          <svg className="w-3.5 h-3.5 text-sky-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                          </svg>
                          <span>Chained Protocols</span>
                        </div>
                        <span
                          className="text-[9px] border px-1.5 py-0.5 rounded font-bold"
                          style={{
                            backgroundColor: 'color-mix(in srgb, var(--foreground) 8%, transparent)',
                            borderColor: 'color-mix(in srgb, var(--foreground) 15%, transparent)',
                            color: 'var(--foreground)',
                          }}
                        >
                          Multi-Scheme
                        </span>
                      </div>
                      <span className="font-bold text-sm" style={{ color: 'var(--foreground)' }}>
                        {result.smuggling.schemes_found && result.smuggling.schemes_found.length > 0 
                          ? result.smuggling.schemes_found.join(' + ').toUpperCase() 
                          : 'HTTP / FTP'}
                      </span>
                      <span className="text-[10px] opacity-50 font-sans">Protocol Smuggling Flag</span>
                    </div>

                    {/* Card 3: Quarantined Target */}
                    <div
                      className="p-3.5 rounded-2xl border flex flex-col justify-between gap-2"
                      style={{
                        backgroundColor: 'color-mix(in srgb, var(--foreground) 4%, transparent)',
                        borderColor: 'color-mix(in srgb, var(--foreground) 10%, transparent)',
                      }}
                    >
                      <div className="flex items-center justify-between text-[10px] uppercase font-bold opacity-60">
                        <div className="flex items-center gap-1.5">
                          <svg className="w-3.5 h-3.5 text-rose-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="22" y1="12" x2="18" y2="12"/>
                            <line x1="6" y1="12" x2="2" y2="12"/>
                            <line x1="12" y1="6" x2="12" y2="2"/>
                            <line x1="12" y1="22" x2="12" y2="18"/>
                          </svg>
                          <span>Isolated Target</span>
                        </div>
                        <span className="text-[9px] bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30 px-1.5 py-0.5 rounded font-bold">
                          Quarantined
                        </span>
                      </div>
                      <span className="text-rose-600 dark:text-rose-400 font-bold text-sm truncate" title={result.active_payload_domain || result.smuggling.active_payload_domain}>
                        {result.active_payload_domain || result.smuggling.active_payload_domain}
                      </span>
                      <span className="text-[10px] text-rose-600/80 dark:text-rose-400/80 font-sans">Active Payload Analyzed</span>
                    </div>
                  </div>
                </motion.div>
              )}

              {/* DUAL COMPARISON GRID: Heuristic Baseline vs. AI Risk Assessment */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Left Card: Original Heuristic */}
                <div
                  className="p-6 rounded-3xl border flex flex-col items-center justify-between text-center relative overflow-hidden"
                  style={{ borderColor: 'color-mix(in srgb, var(--foreground) 10%, transparent)', backgroundColor: 'var(--muted)' }}
                >
                  <div className="text-[10px] uppercase font-bold tracking-widest opacity-50 mb-1">
                    Rule-Based Trust Score
                  </div>
                  <ScoreArc score={result.score} />
                  <p className={`text-xl font-black uppercase tracking-tight mt-2 ${verdictColor(result.verdict)}`}>
                    {result.verdict}
                  </p>
                  <p className="text-[11px] opacity-40 max-w-xs mt-1">
                    Evaluates domain age, email authentication & security headers
                  </p>
                </div>

                {/* Right Card: AI Threat Engine */}
                <div
                  className="p-6 rounded-3xl border flex flex-col justify-between text-left relative overflow-hidden bg-gradient-to-br from-indigo-950/20 via-slate-900/40 to-cyan-950/20"
                  style={{ borderColor: 'color-mix(in srgb, var(--foreground) 15%, transparent)' }}
                >
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase font-bold tracking-widest text-indigo-400">
                        AI Threat Assessment
                      </span>
                    </div>

                    <div className="mt-4 flex items-baseline gap-3">
                      <span className="text-4xl font-black tracking-tight">
                        {result.ai ? `${result.ai.composite_ai_risk_score}%` : 'N/A'}
                      </span>
                      <span className={`text-sm font-bold uppercase tracking-wider ${verdictColor(result.ai?.composite_verdict || '')}`}>
                        {result.ai?.composite_verdict?.toLowerCase().includes('risk')
                          ? result.ai?.composite_verdict
                          : `${result.ai?.composite_verdict} Risk`}
                      </span>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full bg-slate-800/80 rounded-full h-2 mt-3 overflow-hidden">
                      <motion.div
                        className={`h-full ${
                          (result.ai?.composite_ai_risk_score ?? 0) >= 70
                            ? 'bg-red-500'
                            : (result.ai?.composite_ai_risk_score ?? 0) >= 45
                            ? 'bg-orange-500'
                            : 'bg-emerald-500'
                        }`}
                        initial={{ width: 0 }}
                        animate={{ width: `${result.ai?.composite_ai_risk_score ?? 0}%` }}
                        transition={{ duration: 0.8 }}
                      />
                    </div>
                  </div>

                  {/* Sub-model signals */}
                  <div className="space-y-2 mt-5 pt-4 border-t border-white/5 text-xs">
                    <div className="flex justify-between items-center">
                      <span className="opacity-60">URL Pattern Risk:</span>
                      <span className="font-mono font-bold">
                        {result.ai?.lexical?.risk_score}%
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="opacity-60">Server Security Risk:</span>
                      <span className="font-mono font-bold">
                        {result.ai?.network_ml?.risk_score}%
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="opacity-60">Behavioral Anomaly:</span>
                      <span className={`font-mono font-bold ${result.ai?.anomaly?.zero_day_suspect ? 'text-amber-400' : 'text-slate-300'}`}>
                        {result.ai?.anomaly?.zero_day_suspect ? 'Unusual Setup Detected' : result.ai?.anomaly?.anomaly_level === 'Normal' ? 'Standard Patterns' : 'Elevated Variance'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* RAG MITRE ATT&CK SECURITY ANALYST REPORT */}
              {result.analyst_report && (
                <div
                  className="p-6 sm:p-8 rounded-3xl border space-y-6 relative overflow-hidden"
                  style={{ borderColor: 'color-mix(in srgb, var(--foreground) 15%, transparent)', backgroundColor: 'var(--muted)' }}
                >
                  {/* Card Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-white/10">
                    <div>
                      <h2 className="text-base font-bold uppercase tracking-wider">
                        Security Intelligence Briefing
                      </h2>
                      <p className="text-[11px] opacity-40">
                        Automated assessment mapped against cybersecurity industry frameworks
                      </p>
                    </div>
                    <span className={`self-start sm:self-auto px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider border ${threatBadgeColor(result.analyst_report.threat_level)}`}>
                      {result.analyst_report.threat_level}
                    </span>
                  </div>

                  {/* Executive Summary */}
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/5 space-y-1">
                    <span className="text-[10px] uppercase font-bold tracking-widest opacity-40">
                      Executive Summary
                    </span>
                    <p className="text-sm font-medium leading-relaxed">
                      {result.analyst_report.executive_summary}
                    </p>
                  </div>

                  {/* Technical Evidence */}
                  {result.analyst_report.technical_evidence?.length > 0 && (
                    <div className="space-y-2">
                      <span className="text-[10px] uppercase font-bold tracking-widest opacity-40">
                        Observed Risk Factors
                      </span>
                      <ul className="space-y-1.5">
                        {result.analyst_report.technical_evidence.map((ev, i) => (
                          <li key={i} className="text-xs flex gap-2 items-start opacity-80">
                            <span className="text-indigo-400 mt-0.5">•</span>
                            <span>{ev}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* MITRE ATT&CK Mapping */}
                  {result.analyst_report.mitre_attack_mappings?.length > 0 && (
                    <div className="space-y-3">
                      <span className="text-[10px] uppercase font-bold tracking-widest opacity-40">
                        Mapped Security Threat Patterns (MITRE ATT&CK)
                      </span>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                        {result.analyst_report.mitre_attack_mappings.map((m) => (
                          <div key={m.technique_id} className="p-3 rounded-xl bg-white/[0.02] border border-white/5 space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-mono font-bold text-indigo-400">{m.technique_id}</span>
                              <span className="text-[10px] opacity-40 uppercase">{m.tactics.join(', ')}</span>
                            </div>
                            <p className="text-xs font-semibold">{m.name}</p>
                            <p className="text-[11px] opacity-60 line-clamp-2 leading-relaxed">{m.description}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Actionable Recommendations */}
                  {result.analyst_report.actionable_recommendations?.length > 0 && (
                    <div className="space-y-2 pt-2 border-t border-white/10">
                      <span className="text-[10px] uppercase font-bold tracking-widest text-emerald-400">
                        Recommended Safety Actions
                      </span>
                      <ul className="space-y-1.5">
                        {result.analyst_report.actionable_recommendations.map((rec, i) => (
                          <li key={i} className="text-xs flex gap-2 items-start text-emerald-300/90 font-medium">
                            <span className="text-emerald-400">✓</span>
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Community Threat Intelligence Sharing Card */}
              {result && (
                ((result.ai?.composite_ai_risk_score ?? 0) >= 45 ||
                 result.analyst_report?.threat_level === 'CRITICAL' ||
                 result.analyst_report?.threat_level === 'ELEVATED') ? (
                  <div
                    className="p-5 rounded-3xl border border-red-500/30 bg-gradient-to-r from-red-950/20 via-slate-900/40 to-slate-900/20 flex flex-col sm:flex-row items-center justify-between gap-4"
                    style={{ borderColor: 'color-mix(in srgb, var(--foreground) 12%, transparent)' }}
                  >
                    <div className="space-y-1 text-left">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
                        <h4 className="text-xs uppercase tracking-widest font-bold text-red-400">
                          Community Threat Defense
                        </h4>
                      </div>
                      <p className="text-xs opacity-70">
                        Elevated risk detected. Help safeguard the broader ecosystem by reporting this verified indicator to public blocklists.
                      </p>
                    </div>
                    <button
                      onClick={() => {
                        setReportSuccess(null);
                        setReportError('');
                        setReportModalOpen(true);
                      }}
                      className="px-4 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider bg-red-500 hover:bg-red-600 text-white transition-all shadow-lg shadow-red-500/20 active:scale-95 shrink-0"
                    >
                      Report Threat IoC
                    </button>
                  </div>
                ) : (
                  <div className="p-3.5 px-5 rounded-2xl border border-white/5 bg-white/[0.02] flex items-center justify-between text-xs opacity-50">
                    <span>Public threat reporting is restricted to verified risk indicators.</span>
                    <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400">
                      Protected Domain
                    </span>
                  </div>
                )
              )}

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
                      <li key={i} className="text-sm text-orange-400 flex gap-2.5 items-start p-3 rounded-xl" style={{ backgroundColor: 'color-mix(in srgb, var(--foreground) 4%, transparent)' }}>
                        <svg className="w-4 h-4 shrink-0 text-orange-400 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
                          <line x1="12" y1="9" x2="12" y2="13"/>
                          <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        <span>{w.replace(/^⚠\s*/, '')}</span>
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

        {/* Community Threat Submission Modal */}
        <AnimatePresence>
          {reportModalOpen && result && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-sm overflow-y-auto overscroll-contain">
              <motion.div
                initial={{ opacity: 0, scale: 0.96, y: 12 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.96, y: 12 }}
                transition={{ duration: 0.2, ease: "easeOut" }}
                className="w-full max-w-md my-auto max-h-[calc(100dvh-1.5rem)] sm:max-h-[90vh] flex flex-col rounded-3xl border border-white/10 bg-slate-950 text-slate-100 shadow-2xl relative overflow-hidden"
              >
                {/* Fixed Modal Header */}
                <div className="p-4 sm:p-5 pb-3 border-b border-white/10 shrink-0 relative pr-12 text-left">
                  <button
                    type="button"
                    onClick={() => setReportModalOpen(false)}
                    className="absolute top-3.5 right-3.5 text-slate-400 hover:text-white p-2 rounded-xl hover:bg-white/5 transition-colors"
                    aria-label="Close modal"
                  >
                    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="18" y1="6" x2="6" y2="18"/>
                      <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                  </button>
                  <span className="text-[10px] uppercase font-bold tracking-widest text-red-400 block">
                    Community Threat Defense
                  </span>
                  <h3 className="text-base sm:text-lg font-bold text-white">Publish Threat IoC</h3>
                  <p className="text-xs opacity-60 mt-0.5 line-clamp-1">
                    Submit verified malicious targets to public security blocklists.
                  </p>
                </div>

                {/* Scrollable Modal Body */}
                <div className="p-4 sm:p-5 overflow-y-auto overscroll-contain space-y-3.5 text-left text-xs flex-1 min-h-0">
                  {reportSuccess ? (
                    <div className="p-4 sm:p-5 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 space-y-3 text-left">
                      <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                        <svg className="w-4 h-4 text-emerald-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="20 6 9 17 4 12"/>
                        </svg>
                        <span>Threat IoC Successfully Dispatched</span>
                      </div>
                      <div className="text-xs space-y-1 font-mono opacity-80 break-all">
                        <p>Report ID: {reportSuccess.report?.report_id}</p>
                        <p>Status: {reportSuccess.report?.status}</p>
                        <p>Target: {reportSuccess.report?.domain}</p>
                      </div>
                      <div className="pt-2 flex flex-wrap gap-2">
                        <a
                          href={reportSuccess.external_submission_urls?.urlhaus}
                          target="_blank"
                          rel="noreferrer"
                          className="px-3 py-1.5 rounded-lg text-xs font-bold bg-emerald-500 hover:bg-emerald-600 text-slate-950 transition-colors"
                        >
                          View URLhaus Feed ↗
                        </a>
                        <button
                          onClick={() => setReportModalOpen(false)}
                          className="px-3 py-1.5 rounded-lg text-xs font-bold border border-white/20 hover:bg-white/5 transition-colors"
                        >
                          Done
                        </button>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5 space-y-2">
                        {result.smuggling?.is_concatenated && (
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-emerald-400 font-bold border-b border-white/5 pb-2">
                            <div className="flex items-center gap-1.5 shrink-0">
                              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                              </svg>
                              <span>Shielded Lure Domain:</span>
                            </div>
                            <div className="flex items-center gap-1.5 min-w-0 max-w-full">
                              <span className="font-mono truncate text-emerald-200" title={result.lure_prefix_domain || result.smuggling.lure_prefix_domain}>
                                {result.lure_prefix_domain || result.smuggling.lure_prefix_domain}
                              </span>
                              <span className="text-[9px] font-sans px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 shrink-0">
                                Universal Immunity
                              </span>
                            </div>
                          </div>
                        )}
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-0.5">
                          <span className="opacity-50 shrink-0">Target Host / Payload:</span>
                          <span className="font-mono font-bold text-red-300 truncate max-w-full" title={result.active_payload_domain || result.domain}>
                            {result.active_payload_domain || result.domain}
                          </span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="opacity-50">Assessed Threat:</span>
                          <span className="font-bold text-red-400">{result.analyst_report?.threat_level || 'ELEVATED'}</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="opacity-50">Target Registries:</span>
                          <span className="opacity-80 truncate text-right">URLhaus & PhishTank</span>
                        </div>
                      </div>

                      {reportError && (
                        <p className="text-red-400 text-xs p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 break-words">
                          {reportError}
                        </p>
                      )}

                      {/* Interactive Object-Selection CAPTCHA Challenge */}
                      <CaptchaPuzzle
                        isVerified={humanVerified}
                        onVerified={(verified) => setHumanVerified(verified)}
                      />
                    </>
                  )}
                </div>

                {/* Fixed Modal Footer with Actions */}
                {!reportSuccess && (
                  <div className="p-3.5 sm:p-5 pt-3 border-t border-white/10 shrink-0 bg-slate-950 flex gap-2.5">
                    <button
                      type="button"
                      onClick={() => setReportModalOpen(false)}
                      className="w-1/3 py-2.5 rounded-xl font-bold uppercase tracking-wider text-xs border border-white/10 hover:bg-white/5 transition-colors text-slate-300"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={handleReportThreat}
                      disabled={!humanVerified || submittingReport}
                      className="w-2/3 py-2.5 rounded-xl font-bold uppercase tracking-wider text-xs bg-red-500 hover:bg-red-600 disabled:opacity-40 text-white transition-all shadow-lg shadow-red-500/20 active:scale-95 flex items-center justify-center gap-1.5"
                    >
                      {submittingReport ? (
                        <>
                          <svg className="animate-spin w-3.5 h-3.5 text-white" viewBox="0 0 24 24" fill="none">
                            <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeDasharray="31.4" strokeDashoffset="10" />
                          </svg>
                          <span>Submitting...</span>
                        </>
                      ) : (
                        'Publish IoC Report'
                      )}
                    </button>
                  </div>
                )}
              </motion.div>
            </div>
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
