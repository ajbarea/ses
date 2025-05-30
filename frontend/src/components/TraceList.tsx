export default function TraceList({
  explanations,
}: {
  explanations: { rule: string; activation: string }[];
}) {
  return (
    <div>
      <h3 className="font-medium">Rule Trace:</h3>
      <ul className="list-decimal list-inside">
        {explanations.map((e, i) => (
          <li key={i}>{e.activation}</li>
        ))}
      </ul>
    </div>
  );
}
