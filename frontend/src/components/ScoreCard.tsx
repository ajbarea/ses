export default function ScoreCard({
  score,
  grade,
}: {
  readonly score: number;
  readonly grade: string;
}) {
  // map custom grade strings to Tailwind color classes
  const gradeColor = (() => {
    switch (grade) {
      case "Excellent":
        return "text-green-500 bg-green-50 border-green-200";
      case "Good":
        return "text-green-600 bg-green-50 border-green-200";
      case "Fair":
        return "text-yellow-600 bg-yellow-50 border-yellow-200";
      case "Poor":
        return "text-orange-600 bg-orange-50 border-orange-200";
      case "Critical Risk":
      default:
        return "text-red-600 bg-red-50 border-red-200";
    }
  })();

  return (
    <div className="flex items-center justify-between">
      <h2 className="text-2xl font-semibold text-gray-800">
        Security Score: <span>{score}</span>
      </h2>
      <div className={`px-4 py-1 rounded-full border ${gradeColor}`}>
        <span className="font-medium">{grade}</span>
      </div>
    </div>
  );
}
