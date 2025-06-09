export interface Finding {
  rule: string;
  level: string;
  description: string;
  recommendation?: string;
  details?: string[];
  score_impact?: {
    value: number;
    type: "bonus" | "penalty" | "neutral";
  };
  score_text?: string;
  [key: string]: any;
}

export interface AntivirusProduct {
  name: string;
  state?: number | null;
}

export interface AntivirusInfo {
  products: AntivirusProduct[];
  status?: "enabled" | "disabled" | "partial";
  definitions?: "up-to-date" | "out-of-date";
  realTimeProtection?: "enabled" | "disabled";
}

export interface EvalResult {
  score: number;
  grade: string;
  summary: string;
  impact_summary?: string;
  findings: Finding[];
  positive_findings?: Finding[];
  negative_findings?: Finding[];
  neutral_findings?: Finding[];
  rules_fired: number;
  explanations: { rule: string; activation: string }[];
  metrics: {
    antivirus?: AntivirusInfo;
    [key: string]: any;
  };
}
