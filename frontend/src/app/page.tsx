// frontend/src/app/page.tsx
"use client";

import { useState, useEffect } from "react";
import ScanButton from "../components/ScanButton";
import ScanProgress from "../components/ScanProgress";
import ResultsDisplay from "../components/ResultsDisplay";

interface Finding {
  rule: string;
  description: string;
  [key: string]: any;
}

interface EvalResult {
  score: number;
  grade: string;
  summary: string;
  findings: Finding[];
  rules_fired: number;
  explanations: { rule: string; activation: string }[];
  metrics: Record<string, any>;
}

export default function Home() {
  const [result, setResult] = useState<EvalResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [backendError, setBackendError] = useState<string | null>(null); // For errors from Electron main
  const [progress, setProgress] = useState(0);

  // Define types for the exposed Electron API
  interface ElectronAPI {
    onBackendError: (callback: (error: string) => void) => void;
    removeBackendErrorListeners: () => void;
  }

  // Extend the Window interface
  declare global {
    interface Window {
      electronAPI?: ElectronAPI;
    }
  }

  const API = process.env.NEXT_PUBLIC_API_URL;

  useEffect(() => {
    if (window.electronAPI) {
      const handleBackendError = (eventError: string) => {
        console.error("Received backend error via IPC:", eventError);
        setBackendError(`A critical backend process error occurred: ${eventError}. Please try restarting the application.`);
        // Optionally, clear other results or stop loading states
        setResult(null);
        setLoading(false);
        setProgress(0);
      };

      window.electronAPI.onBackendError(handleBackendError);

      return () => {
        if (window.electronAPI) {
          window.electronAPI.removeBackendErrorListeners();
        }
      };
    }
  }, []);

  const runEvaluation = async () => {
    setLoading(true);
    setError(null);
    setBackendError(null); // Clear backend errors on new scan
    setResult(null);
    setProgress(0);

    const interval = setInterval(() => {
      setProgress((p) => (p < 90 ? p + 10 : p));
    }, 400);

    try {
      const res = await fetch(`${API}/evaluate`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: EvalResult = await res.json();
      setResult(data);
      setProgress(100);
    } catch (err: any) {
      setError(err.message);
    } finally {
      clearInterval(interval);
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4 space-y-6 bg-gray-50">
      <div className="w-full max-w-2xl flex flex-col items-center">
        <ScanButton
          onClick={runEvaluation}
          loading={loading}
          icon="./shield.svg"
        >
          {result ? "Re-scan" : "Start Security Scan"}
        </ScanButton>

        {!result && loading && (
          <div className="mt-6 w-full flex justify-center">
            <ScanProgress progress={progress} loading={loading} />
          </div>
        )}

        {error && (
          <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-lg w-full">
            <p className="text-red-600">API Error: {error}</p>
          </div>
        )}

        {backendError && (
          <div className="mt-6 p-4 bg-orange-50 border border-orange-200 rounded-lg w-full">
            <p className="text-orange-700">System Error: {backendError}</p>
          </div>
        )}
      </div>

      {result && !backendError && (
        <div className="animate-fadeIn w-full max-w-2xl">
          <ResultsDisplay result={result} />
        </div>
      )}
    </div>
  );
}
