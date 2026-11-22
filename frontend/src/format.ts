// Small pure helpers for displaying numbers, sizes and times. Pure = easy to unit-test.

const integer = new Intl.NumberFormat("en-US");

export function formatCount(n: number | null | undefined): string {
  return n === null || n === undefined ? "–" : integer.format(n);
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "–";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${value} B` : `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "–";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  if (minutes < 60) return `${minutes} min ${rest} s`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

/** Unix seconds -> "2026-11-20 15:22:45" in the viewer's local time. */
export function formatTime(unixSeconds: number | null | undefined): string {
  if (unixSeconds === null || unixSeconds === undefined) return "–";
  const d = new Date(unixSeconds * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

/** Seconds since the capture started, e.g. "+12.4 s". */
export function formatOffset(unixSeconds: number, captureStart: number | null): string {
  if (captureStart === null) return formatTime(unixSeconds);
  const delta = unixSeconds - captureStart;
  // A time bucket can start slightly before the first packet: show "-0.3 s", not "+-0.3 s".
  return `${delta < 0 ? "-" : "+"}${Math.abs(delta).toFixed(1)} s`;
}

export function endpoint(ip: string, port: number | null): string {
  if (port === null) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/** Fill the gaps between non-empty timeline buckets with zeros so a line chart is honest. */
export function fillTimeline(
  buckets: { start: number; packets: number; bytes: number }[],
  bucketSeconds: number,
  maxPoints = 2000,
): { start: number; packets: number; bytes: number }[] {
  if (buckets.length === 0) return [];
  const first = buckets[0].start;
  const last = buckets[buckets.length - 1].start;
  const count = Math.round((last - first) / bucketSeconds) + 1;
  if (count > maxPoints) return buckets; // too long to densify: show only real points
  const byStart = new Map(buckets.map((b) => [Math.round((b.start - first) / bucketSeconds), b]));
  return Array.from({ length: count }, (_, i) => {
    const existing = byStart.get(i);
    return existing ?? { start: first + i * bucketSeconds, packets: 0, bytes: 0 };
  });
}
