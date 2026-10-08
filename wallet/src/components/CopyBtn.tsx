import { useState } from "react";

export default function CopyBtn({ value, label = "copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className={"btn btn-sm btn-copy" + (done ? " copied" : "")}
      aria-label={`Copy ${value.length > 40 ? value.slice(0, 20) + '…' : value} to clipboard`}
      onClick={() => {
        void navigator.clipboard?.writeText(value);
        setDone(true);
        setTimeout(() => setDone(false), 1300);
      }}
    >
      {done ? "✓ copied" : label}
    </button>
  );
}
