type IconName =
  | "squares-four"
  | "list-bullets"
  | "shield-check"
  | "stack"
  | "list"
  | "x"
  | "arrows-down-up"
  | "check"
  | "prohibit"
  | "fingerprint"
  | "pulse"
  | "check-circle"
  | "lock-key"
  | "hard-drives";

const PATHS: Record<IconName, string> = {
  "squares-four":
    "M4 4h6.5v6.5H4V4Zm9.5 0H20v6.5h-6.5V4ZM4 13.5H10.5V20H4v-6.5Zm9.5 0H20V20h-6.5v-6.5Z",
  "list-bullets":
    "M9 6h12M9 12h12M9 18h12M4.2 6h.01M4.2 12h.01M4.2 18h.01",
  "shield-check":
    "M12 3 4 6.2v5.4c0 5.2 4.2 8.4 8 9.8 3.8-1.4 8-4.6 8-9.8V6.2L12 3Z M8.2 12.2l2.6 2.6 5-5.2",
  stack: "M3 7.5 12 4l9 3.5-9 3.5L3 7.5ZM3 12l9 3.5L21 12M3 16.5 12 20l9-3.5",
  list: "M4 7h16M4 12h16M4 17h16",
  x: "M6 6l12 12M18 6 6 18",
  "arrows-down-up": "M7 3v18m-4-4 4 4 4-4M17 21V3m-4 4 4-4 4 4",
  check: "m5 12 4.5 4.5L20 6",
  prohibit: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM6 6l12 12",
  fingerprint:
    "M5 11a7 7 0 0 1 14 0M3.5 9.5A9.5 9.5 0 0 1 12 2m8.5 9c0 4-1 7-2.4 10M8.2 12a3.8 3.8 0 0 1 7.6 0c0 5-1 8-2.7 10M12 11.5c0 4-1.3 7.5-3 9.5M5 14c-.2 2.4-.8 3.8-1.5 5M8 14c-.2 2.4-.8 4-1.6 5.4",
  pulse: "M2 12h5l3-8 4 16 3-8h5",
  "check-circle": "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM8 12.2l2.6 2.6L16.5 9",
  "lock-key": "M8 11V8a4 4 0 0 1 8 0v3M6.5 11h11v9h-11v-9Zm5.5 4.2v2.2",
  "hard-drives": "M4 6.5h16v5H4v-5Zm0 7h16v5H4v-5ZM7 9h.01M7 16h.01M11 9h4M11 16h4",
};

export function Icon({ name }: { name: IconName }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d={PATHS[name]} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
