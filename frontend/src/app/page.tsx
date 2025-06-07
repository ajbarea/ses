// frontend/src/app/page.tsx
"use client";

import { useState } from "react";
import ScoreCard from "../components/ScoreCard";
import FindingsList from "../components/FindingsList";
import TraceList from "../components/TraceList";
import { PulseLoader } from "react-spinners";

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
  const API = process.env.NEXT_PUBLIC_API_URL;

  const runEvaluation = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/evaluate`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: EvalResult = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8">
      <button
        onClick={runEvaluation}
        disabled={loading}
        className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
      >
        {loading ? (
          <PulseLoader size={8} color="#fff" />
        ) : (
          "Run Security Evaluation"
        )}
      </button>

      {error && <p className="mt-4 text-red-500">Error: {error}</p>}

      {result && (
        <div className="mt-6 space-y-4">
          <ScoreCard grade={result.grade} score={result.score} />
          <p>{result.summary}</p>
          <FindingsList findings={result.findings} />
          <TraceList
            explanations={result.explanations}
            metrics={result.metrics}
          />
        </div>
      )}
    </div>
  );
}
