export default function TraceList({
  explanations,
}: {
  readonly explanations: readonly { rule: string; activation: string }[];
}) {
  return (
    <div>
      <h3 className="font-medium">Rule Trace:</h3>
      <ul className="list-decimal list-inside">
        {explanations.map((e) => (
          <li key={e.rule}>{e.activation}</li>
        ))}
      </ul>
    </div>
  );
}
