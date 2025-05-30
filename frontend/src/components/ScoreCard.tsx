export default function ScoreCard({
  score,
  grade,
}: {
  score: number;
  grade: string;
}) {
  return (
    <h2 className="text-xl">
      Score: {score} — <span className="font-semibold">{grade}</span>
    </h2>
  );
}
