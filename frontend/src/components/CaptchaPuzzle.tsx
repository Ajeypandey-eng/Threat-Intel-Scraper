import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface PuzzleTarget {
  id: string;
  name: string;
  symbol: string;
  instruction: string;
}

const TARGET_TYPES: PuzzleTarget[] = [
  { id: 'shield', name: 'Security Shields', symbol: '🛡️', instruction: 'Select all images containing a Security Shield' },
  { id: 'key', name: 'Access Keys', symbol: '🔑', instruction: 'Select all images containing an Access Key' },
  { id: 'lock', name: 'Cyber Locks', symbol: '🔒', instruction: 'Select all images containing a Cyber Lock' },
  { id: 'brick', name: 'Firewalls', symbol: '🧱', instruction: 'Select all images containing a Firewall' },
];

const DECOYS = ['🚗', '🌲', '☕', '🚲', '✈️', '⭐', '🍎', '⌚', '🎸', '🎨', '🚀', '⚓', '💡', '🔔'];

interface Tile {
  id: number;
  symbol: string;
  isTarget: boolean;
}

interface CaptchaPuzzleProps {
  onVerified: (verified: boolean) => void;
  isVerified: boolean;
}

export const CaptchaPuzzle: React.FC<CaptchaPuzzleProps> = ({ onVerified, isVerified }) => {
  const [currentTarget, setCurrentTarget] = useState<PuzzleTarget>(TARGET_TYPES[0]);
  const [tiles, setTiles] = useState<Tile[]>([]);
  const [selectedIndices, setSelectedIndices] = useState<Set<number>>(new Set());
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [shakeKey, setShakeKey] = useState(0);

  const generatePuzzle = () => {
    // 1. Pick a random target category
    const target = TARGET_TYPES[Math.floor(Math.random() * TARGET_TYPES.length)];
    setCurrentTarget(target);

    // 2. Decide how many target tiles (3 or 4 out of 9)
    const numTargets = 3 + Math.floor(Math.random() * 2); // 3 or 4
    const targetPositions = new Set<number>();
    while (targetPositions.size < numTargets) {
      targetPositions.add(Math.floor(Math.random() * 9));
    }

    // 3. Pick random decoys without duplicate decoys if possible
    const shuffledDecoys = [...DECOYS].sort(() => Math.random() - 0.5);

    const newTiles: Tile[] = [];
    let decoyIdx = 0;
    for (let i = 0; i < 9; i++) {
      if (targetPositions.has(i)) {
        newTiles.push({
          id: i,
          symbol: target.symbol,
          isTarget: true,
        });
      } else {
        newTiles.push({
          id: i,
          symbol: shuffledDecoys[decoyIdx % shuffledDecoys.length],
          isTarget: false,
        });
        decoyIdx++;
      }
    }

    setTiles(newTiles);
    setSelectedIndices(new Set());
    setErrorMessage(null);
  };

  useEffect(() => {
    if (!isVerified) {
      generatePuzzle();
    }
  }, [isVerified]);

  const toggleSelect = (index: number) => {
    if (isVerified || isVerifying) return;
    setErrorMessage(null);
    setSelectedIndices(prev => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  const handleVerify = () => {
    if (isVerified || isVerifying) return;

    setIsVerifying(true);
    setErrorMessage(null);

    // Simulated short verification delay for realism
    setTimeout(() => {
      // Check if all selected indices are targets and no target was missed
      const actualTargetIndices = tiles
        .map((t, idx) => (t.isTarget ? idx : -1))
        .filter(idx => idx !== -1);

      const hasAllTargets = actualTargetIndices.every(idx => selectedIndices.has(idx));
      const hasNoDecoys = Array.from(selectedIndices).every(idx => tiles[idx]?.isTarget);

      if (hasAllTargets && hasNoDecoys && selectedIndices.size === actualTargetIndices.length) {
        onVerified(true);
        setIsVerifying(false);
      } else {
        setErrorMessage('Verification failed: incorrect selection. Try the new puzzle below.');
        setShakeKey(prev => prev + 1);
        setIsVerifying(false);
        // Automatically generate fresh puzzle so bots cannot brute force
        setTimeout(() => {
          generatePuzzle();
        }, 800);
      }
    }, 450);
  };

  if (isVerified) {
    return (
      <div className="p-3.5 rounded-2xl border border-emerald-500/40 bg-emerald-500/10 flex items-center justify-between transition-all">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 rounded-xl bg-emerald-500 text-slate-950 font-black flex items-center justify-center text-sm shadow-md shadow-emerald-500/30">
            ✓
          </div>
          <div>
            <p className="font-bold text-xs text-emerald-400">Human Identity Confirmed</p>
            <p className="text-[10px] opacity-60">Interactive object-selection puzzle verified</p>
          </div>
        </div>
        <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 font-bold px-2 py-1 bg-emerald-500/20 rounded-md">
          PASSED
        </span>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-4 space-y-3">
      {/* CAPTCHA Header with Target Prompt */}
      <div className="flex items-start justify-between gap-2 border-b border-white/5 pb-2.5">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-indigo-400 font-bold">
              Human Security Challenge
            </span>
            <span className="text-[10px] opacity-40 shrink-0">• 3x3 Grid</span>
          </div>
          <p className="text-xs font-semibold text-white mt-0.5 break-words">
            Select all squares with: <span className="text-indigo-300 underline underline-offset-2 font-bold">{currentTarget.name}</span> {currentTarget.symbol}
          </p>
        </div>
        <button
          type="button"
          onClick={generatePuzzle}
          title="Reload Challenge"
          className="text-xs text-slate-400 hover:text-white p-1.5 rounded-lg border border-white/10 hover:bg-white/5 transition-colors shrink-0"
        >
          ↻ New
        </button>
      </div>

      {/* 3x3 Tiles Grid */}
      <motion.div
        key={shakeKey}
        animate={shakeKey > 0 ? { x: [-6, 6, -4, 4, -2, 2, 0] } : {}}
        transition={{ duration: 0.4 }}
        className="grid grid-cols-3 gap-2 max-w-[280px] mx-auto w-full"
      >
        {tiles.map((tile, idx) => {
          const isSelected = selectedIndices.has(idx);
          return (
            <button
              key={tile.id}
              type="button"
              onClick={() => toggleSelect(idx)}
              className={`relative aspect-square rounded-xl flex items-center justify-center text-2xl transition-all select-none border ${
                isSelected
                  ? 'border-indigo-500 bg-indigo-500/20 ring-2 ring-indigo-500/50 scale-[0.98]'
                  : 'border-white/10 bg-slate-900/60 hover:border-white/20 hover:bg-white/[0.04]'
              }`}
            >
              <span className="transform hover:scale-110 transition-transform">
                {tile.symbol}
              </span>
              {isSelected && (
                <div className="absolute top-1 right-1 w-4 h-4 rounded-full bg-indigo-500 text-slate-950 font-bold text-[10px] flex items-center justify-center">
                  ✓
                </div>
              )}
            </button>
          );
        })}
      </motion.div>

      {/* Error Message */}
      <AnimatePresence>
        {errorMessage && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="text-[11px] text-amber-400 bg-amber-500/10 border border-amber-500/20 p-2 rounded-lg"
          >
            {errorMessage}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Action Footer */}
      <div className="flex items-center justify-between pt-1 text-[11px]">
        <span className="opacity-50 font-mono">
          {selectedIndices.size} selected
        </span>
        <button
          type="button"
          onClick={handleVerify}
          disabled={selectedIndices.size === 0 || isVerifying}
          className="px-3 py-1.5 rounded-lg font-bold bg-indigo-600 hover:bg-indigo-500 disabled:opacity-30 text-white transition-all shadow-md shadow-indigo-600/20 active:scale-95 flex items-center gap-1.5"
        >
          {isVerifying ? (
            <>
              <svg className="animate-spin w-3 h-3 text-white" viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeDasharray="31.4" strokeDashoffset="10" />
              </svg>
              <span>Verifying...</span>
            </>
          ) : (
            <span>Verify Solution</span>
          )}
        </button>
      </div>
    </div>
  );
};
