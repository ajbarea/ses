import React from "react";
import type { Finding } from "../types/eval";

export default function FindingsList({
  findings,
}: {
  readonly findings: readonly Finding[];
}) {
  const getLevelBadge = (level: string) => {
    switch (level) {
      case "critical":
        return "bg-red-100 text-red-800";
      case "warning":
        return "bg-yellow-100 text-yellow-800";
      case "info":
        return "bg-blue-100 text-blue-800";
      case "minor":
        return "bg-purple-100 text-purple-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const getScoreImpactBadge = (impact: Finding["score_impact"]) => {
    if (!impact) return null;

    switch (impact.type) {
      case "bonus":
        return (
          <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
            +{impact.value} points
          </span>
        );
      case "penalty":
        return (
          <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
            {impact.value} points
          </span>
        );
      case "neutral":
        return (
          <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600">
            0 points
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="space-y-3">
      {findings.map((finding) => (
        <div
          key={finding.rule}
          className="bg-white p-3 rounded border border-gray-200 shadow-sm"
        >
          <div className="flex justify-between items-start">
            <div className="flex items-center">
              <span
                className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getLevelBadge(
                  finding.level
                )}`}
              >
                {finding.level}
              </span>
              {getScoreImpactBadge(finding.score_impact)}
            </div>
            <span className="text-xs text-gray-500">{finding.rule}</span>
          </div>

          <p className="mt-2 text-sm text-gray-800">{finding.description}</p>

          {finding.details && finding.details.length > 0 && (
            <div className="mt-2">
              <span className="text-xs font-medium text-gray-500">
                Details:
              </span>
              <span className="ml-1 text-xs text-gray-700">
                {finding.details.join(", ")}
              </span>
            </div>
          )}

          {finding.recommendation && (
            <div className="mt-2">
              <span className="text-xs font-medium text-gray-500">
                Recommendation:
              </span>
              <span className="ml-1 text-xs text-gray-700">
                {finding.recommendation}
              </span>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
