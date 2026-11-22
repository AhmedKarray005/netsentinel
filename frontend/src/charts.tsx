// Charts. Rankings are plain HTML bars (label + bar + value, readable without colour);
// the traffic timeline uses Recharts with a hover crosshair and a data-table fallback.
import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { formatCount, formatOffset, formatTime } from "./format";

/** Read colour tokens from CSS so charts follow light/dark mode. */
function useCssColor(name: string): string {
  const read = () =>
    getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#2a78d6";
  const [value, setValue] = useState(read);
  useEffect(() => {
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    const update = () => setValue(read());
    media?.addEventListener?.("change", update);
    return () => media?.removeEventListener?.("change", update);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name]);
  return value;
}

export interface BarItem {
  label: string;
  value: number;
  title?: string; // extra detail shown on hover
}

/** Horizontal bars, one hue (magnitude), each bar labelled with its name and value. */
export function BarList(props: {
  items: BarItem[];
  format?: (n: number) => string;
  emptyText?: string;
}) {
  const { items, format = formatCount, emptyText = "No data" } = props;
  if (items.length === 0) return <p className="empty">{emptyText}</p>;
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <ul className="barlist" role="list">
      {items.map((item) => (
        <li key={item.label} title={item.title ?? `${item.label}: ${format(item.value)}`}>
          <span className="barlist-label mono">{item.label}</span>
          <span className="barlist-track">
            <span
              className="barlist-bar"
              style={{ width: `${Math.max(0.5, (item.value / max) * 100)}%` }}
            />
          </span>
          <span className="barlist-value">{format(item.value)}</span>
        </li>
      ))}
    </ul>
  );
}

export function recordToBars(record: Record<string, number>, limit = 10): BarItem[] {
  return Object.entries(record)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([label, value]) => ({ label, value }));
}

/** Packets per time bucket. One series, so the title names it and no legend is needed. */
export function TimelineChart(props: {
  points: { start: number; packets: number; bytes: number }[];
  captureStart: number | null;
  bucketSeconds: number;
}) {
  const { points, captureStart, bucketSeconds } = props;
  const stroke = useCssColor("--series-1");
  const grid = useCssColor("--grid");
  const muted = useCssColor("--muted");
  if (points.length === 0) return <p className="empty">No packets</p>;
  const peak = points.reduce((best, p) => (p.packets > best.packets ? p : best), points[0]);

  return (
    <>
      <div
        className="chart"
        role="img"
        aria-label={`Packets per ${bucketSeconds} s. Peak ${peak.packets} packets at ${formatTime(peak.start)}.`}
      >
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={points} margin={{ top: 8, right: 12, bottom: 0, left: 0 }}>
            <CartesianGrid stroke={grid} vertical={false} />
            <XAxis
              dataKey="start"
              type="number"
              domain={["dataMin", "dataMax"]}
              tickFormatter={(t: number) => formatOffset(t, captureStart)}
              stroke={muted}
              tick={{ fontSize: 12 }}
              minTickGap={40}
            />
            <YAxis stroke={muted} tick={{ fontSize: 12 }} width={48} allowDecimals={false} />
            <Tooltip
              cursor={{ stroke: muted, strokeDasharray: "3 3" }}
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const p = payload[0].payload as { start: number; packets: number; bytes: number };
                return (
                  <div className="tt">
                    <div className="tt-label">
                      {formatTime(p.start)} ({formatOffset(p.start, captureStart)})
                    </div>
                    <div className="tt-value">{formatCount(p.packets)} packets</div>
                  </div>
                );
              }}
            />
            <Area
              type="linear"
              dataKey="packets"
              stroke={stroke}
              strokeWidth={2}
              fill={stroke}
              fillOpacity={0.15}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <details className="chart-table">
        <summary>Show as table (busiest 20 intervals)</summary>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th className="num">Packets</th>
                <th className="num">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {[...points]
                .sort((a, b) => b.packets - a.packets)
                .slice(0, 20)
                .map((p) => (
                  <tr key={p.start}>
                    <td>{formatTime(p.start)}</td>
                    <td className="num">{formatCount(p.packets)}</td>
                    <td className="num">{formatCount(p.bytes)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </details>
    </>
  );
}
