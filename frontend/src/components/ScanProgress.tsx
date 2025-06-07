import React from "react";

interface ScanProgressProps {
  readonly progress: number;
  readonly loading: boolean;
}

export default function ScanProgress({ progress, loading }: ScanProgressProps) {
  return (
    <div className="w-full max-w-md flex flex-col items-center space-y-2">
      <div className="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
        <div
          className="h-full bg-blue-500 rounded-full transition-all duration-300 ease-out"
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="text-sm text-gray-700 text-center w-full font-medium">
        {loading ? `Scanning... ${progress}%` : "Ready to scan"}
      </div>
    </div>
  );
}
