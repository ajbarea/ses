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
        return "text-green-500";
      case "Good":
        return "text-green-300";
      case "Fair":
        return "text-yellow-500";
      case "Poor":
        return "text-orange-500";
      case "Critical Risk":
      default:
        return "text-red-500";
    }
  })();

  return (
    <h2 className="text-xl">
      Score: {score} —{" "}
      <span className={`font-semibold ${gradeColor}`}>{grade}</span>
    </h2>
  );
}
