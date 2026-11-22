import { describe, expect, it } from "vitest";
import { endpoint, fillTimeline, formatBytes, formatDuration, formatOffset } from "./format";

describe("format helpers", () => {
  it("formats byte sizes with binary units", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(23_603_864)).toBe("23 MB");
    expect(formatBytes(null)).toBe("–");
  });

  it("formats durations at a readable scale", () => {
    expect(formatDuration(0.18)).toBe("180 ms");
    expect(formatDuration(4.6)).toBe("4.6 s");
    expect(formatDuration(134.5)).toBe("2 min 15 s");
    expect(formatDuration(3 * 3600 + 120)).toBe("3 h 2 min");
  });

  it("shows time relative to the capture start", () => {
    expect(formatOffset(1012.44, 1000)).toBe("+12.4 s");
    expect(formatOffset(999.7, 1000)).toBe("-0.3 s");
  });

  it("brackets IPv6 addresses before the port", () => {
    expect(endpoint("192.168.1.13", 443)).toBe("192.168.1.13:443");
    expect(endpoint("2a01::1", 443)).toBe("[2a01::1]:443");
    expect(endpoint("10.0.0.1", null)).toBe("10.0.0.1");
  });

  it("fills silent intervals with zeros so the timeline does not lie", () => {
    const filled = fillTimeline(
      [
        { start: 100, packets: 5, bytes: 500 },
        { start: 103, packets: 2, bytes: 200 },
      ],
      1,
    );
    expect(filled.map((p) => p.packets)).toEqual([5, 0, 0, 2]);
    expect(filled.map((p) => p.start)).toEqual([100, 101, 102, 103]);
  });

  it("does not densify a timeline that would be too long", () => {
    const sparse = [
      { start: 0, packets: 1, bytes: 1 },
      { start: 1_000_000, packets: 1, bytes: 1 },
    ];
    expect(fillTimeline(sparse, 1)).toHaveLength(2);
  });
});
