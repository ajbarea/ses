export default function TraceList({
  explanations,
}: {
  readonly explanations: readonly { rule: string; activation: string }[];
}) {
  const isClipsAvailable = explanations && explanations.length > 0;

  return (
    <div>
      {isClipsAvailable ? (
        <ul className="list-disc list-outside pl-5 text-gray-800 marker:text-blue-600">
          {explanations.map((e) => (
            <li key={e.rule} className="mb-3 pl-1">
              <div>
                <span className="font-medium text-blue-700">{e.rule}</span>
                <span className="text-gray-500 mx-1">—</span>
                <span className="text-gray-800">
                  {e.activation.replace(`${e.rule} - `, "")}
                </span>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <div>
          <p className="text-sm text-gray-700">
            No rule trace information available.
          </p>
          <p className="text-xs text-amber-700 mt-1 font-medium">
            CLIPS rule engine might not be available in this build. The system
            is using the basic rule engine instead.
          </p>
        </div>
      )}
    </div>
  );
}
