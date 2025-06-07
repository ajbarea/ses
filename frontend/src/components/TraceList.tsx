export default function TraceList({
  explanations,
  metrics,
}: {
  readonly explanations: readonly { rule: string; activation: string }[];
  readonly metrics: Record<string, any>;
}) {
  const isClipsAvailable = explanations && explanations.length > 0;

  return (
    <div>
      <h3 className="font-medium">Rule Trace:</h3>
      {isClipsAvailable ? (
        <ul className="list-decimal list-inside">
          {explanations.map((e) => (
            <li key={e.rule}>
              <strong>{e.rule}:</strong> {e.activation}
            </li>
          ))}
        </ul>
      ) : (
        <div>
          <p className="text-sm text-gray-500">
            No rule trace information available.
          </p>
          <p className="text-xs text-amber-600 mt-1">
            CLIPS rule engine might not be available in this build. The system
            is using the basic rule engine instead.
          </p>
        </div>
      )}

      {metrics && (
        <div className="mt-4">
          <h3 className="font-medium">Evaluation Metrics:</h3>
          <pre className="mt-2 p-2 bg-gray-100 rounded text-sm overflow-x-auto text-gray-800">
            {JSON.stringify(metrics, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
