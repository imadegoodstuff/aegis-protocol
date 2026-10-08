import { useState } from "react";

export default function CopyBtn({ value, label = "copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className={"btn btn-sm btn-copy" + (done ? " copied" : "")}
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
