export default function ScoreCard({
  score,
  grade,
}: {
  score: number;
  grade: string;
}) {
  // map grade to a Tailwind color class
  const gradeColor = grade.startsWith("A")
    ? "text-green-500"
    : grade.startsWith("B")
    ? "text-yellow-500"
    : "text-red-500";

  return (
    <h2 className="text-xl">
      Score: {score} —{" "}
      <span className={`font-semibold ${gradeColor}`}>{grade}</span>
    </h2>
  );
}
