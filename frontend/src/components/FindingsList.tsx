interface Finding {
  rule: string;
  description: string;
  [key: string]: any;
}
export default function FindingsList({ findings }: { findings: Finding[] }) {
  return (
    <div>
      <h3 className="font-medium">Findings ({findings.length}):</h3>
      <ul className="list-disc list-inside">
        {findings.map((f, i) => (
          <li key={i}>
            <strong>[{f.rule}]</strong> {f.description}
          </li>
        ))}
      </ul>
    </div>
  );
}
