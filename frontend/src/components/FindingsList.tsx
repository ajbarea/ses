import { useState } from "react";

interface Finding {
  rule: string;
  description: string;
  [key: string]: any;
}

function FindingItem({ f }: { readonly f: Finding }) {
  const [open, setOpen] = useState(false);
  const isLong = f.description.length > 100;
  const displayed =
    isLong && !open ? f.description.slice(0, 100) + "…" : f.description;

  return (
    <li className="mb-2">
      <strong>[{f.rule}]</strong> <span>{displayed}</span>
      {isLong && (
        <button
          onClick={() => setOpen(!open)}
          className="ml-2 text-blue-500 hover:underline text-sm"
        >
          {open ? "Show less" : "Show more"}
        </button>
      )}
      {f.details && (
        <span className="ml-2 text-xs text-gray-600">
          (Details:{" "}
          {Array.isArray(f.details) ? f.details.join(", ") : String(f.details)})
        </span>
      )}
    </li>
  );
}

export default function FindingsList({
  findings,
}: {
  readonly findings: readonly Finding[];
}) {
  return (
    <div>
      <h3 className="font-medium">Findings ({findings.length}):</h3>
      <ul className="list-disc list-inside">
        {findings.map((f) => (
          <FindingItem key={f.rule} f={f} />
        ))}
      </ul>
    </div>
  );
}
