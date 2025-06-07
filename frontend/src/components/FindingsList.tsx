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
    <li className="mb-3 pl-1">
      <div>
        <span className="font-medium text-blue-700">{f.rule}</span>
        <span className="text-gray-500 mx-1">—</span>
        <span className="text-gray-800">{displayed}</span>
        {isLong && (
          <button
            onClick={() => setOpen(!open)}
            className="ml-2 text-blue-600 hover:underline text-sm font-medium"
          >
            {open ? "Show less" : "Show more"}
          </button>
        )}
      </div>
      {f.details && (
        <div className="mt-1 text-xs text-gray-700 ml-4">
          <span className="font-medium">Details:</span>{" "}
          {Array.isArray(f.details) ? f.details.join(", ") : String(f.details)}
        </div>
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
      <ul className="list-disc list-outside pl-5 text-gray-800 marker:text-blue-600">
        {findings.map((f) => (
          <FindingItem key={f.rule} f={f} />
        ))}
      </ul>
    </div>
  );
}
