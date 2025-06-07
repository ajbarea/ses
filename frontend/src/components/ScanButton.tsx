import { ReactNode } from "react";
import { PulseLoader } from "react-spinners";

interface ScanButtonProps {
  readonly onClick: () => void;
  readonly loading: boolean;
  readonly variant?: "primary" | "text";
  readonly children?: ReactNode;
  readonly icon?: string;
  readonly loadingText?: string;
}

export default function ScanButton({
  onClick,
  loading,
  variant = "primary",
  children,
  icon,
  loadingText = "Scanning...",
}: ScanButtonProps) {
  const primaryClasses =
    "min-w-64 h-20 px-6 bg-blue-600 text-white rounded-xl focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center text-xl font-semibold shadow-lg transition-all";
  const textClasses =
    "block mx-auto text-sm text-blue-600 underline disabled:opacity-50";

  const buttonClasses = variant === "primary" ? primaryClasses : textClasses;

  // Extract nested ternary operations completely
  let buttonContent;
  if (loading) {
    buttonContent =
      variant === "primary" ? (
        <PulseLoader size={8} color="#fff" />
      ) : (
        loadingText
      );
  } else {
    buttonContent = (
      <div className="flex items-center justify-center">
        {icon && variant === "primary" && (
          <img
            src={icon}
            alt="Button Icon"
            className="w-9 h-9 mr-3 flex-shrink-0"
          />
        )}
        <span>{children}</span>
      </div>
    );
  }

  return (
    <button onClick={onClick} disabled={loading} className={buttonClasses}>
      {buttonContent}
    </button>
  );
}
