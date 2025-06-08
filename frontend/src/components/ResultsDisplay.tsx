import { useState } from "react";
import ScoreCard from "./ScoreCard";
import FindingsList from "./FindingsList";
import TraceList from "./TraceList";

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

export default function ResultsDisplay({
  result,
}: {
  readonly result: EvalResult;
}) {
  const [activeTab, setActiveTab] = useState<"findings" | "trace" | "metrics">(
    "findings"
  );

  const tabs = [
    { id: "findings", label: `Findings (${result.findings.length})` },
    { id: "trace", label: "Rule Trace" },
    { id: "metrics", label: "Evaluation Metrics" },
  ];

  // Function to generate a recommendation based on score and findings
  const getRecommendation = () => {
    if (result.score >= 90) {
      return "Your system has strong security measures in place. Continue regular monitoring for optimal protection.";
    } else if (result.score >= 70) {
      return "Your system has good security, with some areas that could be strengthened. Review the findings for specific details.";
    } else if (result.score >= 50) {
      return "Some security measures are in place, but several improvements are recommended. Review the findings for details.";
    } else {
      return "Significant security improvements are recommended. Please review all findings to strengthen your system's protection.";
    }
  };

  // Calculate scan timestamp
  const scanTime = new Date().toLocaleString();

  return (
    <div className="w-full max-w-2xl bg-white rounded-lg shadow-sm p-6 transition-all duration-300 ease-in-out">
      <ScoreCard grade={result.grade} score={result.score} />

      <div className="my-4 p-4 bg-gray-50 border border-gray-200 rounded-md">
        <div className="flex justify-between items-start mb-2">
          <h3 className="text-sm font-medium text-gray-700">Scan Summary</h3>
          <span className="text-xs text-gray-500">{scanTime}</span>
        </div>

        <p className="text-gray-800 mb-2">{getRecommendation()}</p>

        <div className="flex items-center text-sm mt-2">
          <div className="mr-4">
            <span className="font-medium text-gray-700">Results: </span>
            <span className="text-gray-600 font-medium">
              {result.findings.length} finding
              {result.findings.length !== 1 ? "s" : ""}
            </span>
          </div>
          <div>
            <span className="font-medium text-gray-700">Rules checked: </span>
            <span className="text-gray-600">{result.rules_fired}</span>
          </div>
        </div>
      </div>

      <div className="mb-4 p-3 bg-blue-50 border border-blue-100 rounded-md">
        <p className="text-sm text-blue-700">
          <strong>Findings:</strong> Security checks and their results -
          includes both security strengths and potential concerns.
          <br />
          <strong>Rule Trace:</strong> Technical details about which security
          rules were activated.
          <br />
          <strong>Evaluation Metrics:</strong> Raw data and performance metrics
          from the scan.
        </p>
      </div>

      <div className="border-b border-gray-200 mb-4">
        <nav className="-mb-px flex space-x-6">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() =>
                setActiveTab(tab.id as "findings" | "trace" | "metrics")
              }
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? "border-blue-500 text-blue-700"
                  : "border-transparent text-gray-600 hover:text-gray-800 hover:border-gray-300"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="mt-4">
        {activeTab === "findings" && (
          <div className="p-3 bg-gray-100 rounded text-sm overflow-x-auto text-gray-800">
            <FindingsList findings={result.findings} />
          </div>
        )}

        {activeTab === "trace" && (
          <div className="p-3 bg-gray-100 rounded text-sm overflow-x-auto text-gray-800">
            <TraceList explanations={result.explanations} />
          </div>
        )}

        {activeTab === "metrics" && (
          <div>
            <h3 className="font-medium text-gray-900 mb-2">
              Evaluation Metrics:
            </h3>
            <pre className="p-3 bg-gray-100 rounded text-sm overflow-x-auto text-gray-800">
              {JSON.stringify(result.metrics, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
