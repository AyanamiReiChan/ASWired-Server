// Traffic quotas use SI bytes, matching provider billing and ASWired.
export function formatTrafficBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) {
    size /= 1000;
    unit++;
  }
  return `${unit === 0 ? Math.round(size) : size.toFixed(2)} ${units[unit]}`;
}

export function parseTrafficBytes(input: string): number {
  const match = input.trim().replace(/,/g, "").match(/^(\d+(?:\.\d*)?|\.\d+)(?:\s*)([kmgtp]?i?b)?$/i);
  if (!match) return 0;
  const unit = (match[2] || "b").toLowerCase();
  const exponent = "bkmgtp".indexOf(unit[0]);
  if (exponent < 0 || unit === "ib") return 0;
  const bytes = Math.round(Number(match[1]) * (unit.includes("i") ? 1024 : 1000) ** exponent);
  return Number.isSafeInteger(bytes) && bytes >= 0 ? bytes : 0;
}
