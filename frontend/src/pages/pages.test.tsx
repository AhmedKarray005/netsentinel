import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api";
import { AnalysisProvider } from "../state";
import type { Alert } from "../types";
import { AlertCard } from "./AlertsPage";
import { UploadPage, uploadErrorText } from "./UploadPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const ALERT: Alert = {
  id: 1,
  analysis_id: 1,
  rule_id: "NS-001",
  rule_name: "Port scan indicator",
  mitre_attack: "T1046 Network Service Discovery",
  severity: "high",
  start: 1795188165.2,
  end: 1795188169.8,
  start_iso: "2026-11-20T15:22:45+00:00",
  src_ip: "127.0.0.1",
  dst_ip: "127.0.0.1",
  dst_port: null,
  summary: "127.0.0.1 contacted 199 distinct ports on 127.0.0.1 in 4.6 s (198 failed)",
  thresholds: { window_seconds: 60, min_distinct_ports: 20 },
  evidence: { distinct_ports: 199, ports_sample: ["TCP/1", "TCP/2"] },
};

describe("AlertCard", () => {
  it("shows severity as text (not colour only), the summary and the evidence", () => {
    render(<AlertCard alert={ALERT} />);
    expect(screen.getByText("High")).toBeTruthy();
    expect(screen.getByText(/199 distinct ports/)).toBeTruthy();
    expect(screen.getByText("distinct ports")).toBeTruthy();
    expect(screen.getByText("TCP/1, TCP/2")).toBeTruthy();
    expect(screen.getByText("T1046 Network Service Discovery")).toBeTruthy();
  });
});

describe("UploadPage", () => {
  it("maps API status codes to actionable messages", () => {
    expect(uploadErrorText(new ApiError(413, "too big"))).toContain("upload limit");
    expect(uploadErrorText(new ApiError(415, "x"))).toContain(".pcapng");
    expect(uploadErrorText(new ApiError(422, "wrong file signature"))).toContain("wrong file signature");
  });

  it("shows the server's rejection when a fake capture is uploaded", async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        return json(422, { detail: "Not a PCAP/PCAPNG file (wrong file signature)" });
      }
      if (url.startsWith("/api/analyses")) return json(200, { items: [], total: 0, limit: 100, offset: 0 });
      return json(404, { detail: "unexpected" });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <MemoryRouter>
        <AnalysisProvider>
          <UploadPage />
        </AnalysisProvider>
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await user.upload(screen.getByLabelText("Capture file"), new File(["hello"], "notes.pcap"));
    await user.click(screen.getByRole("button", { name: "Upload and analyze" }));

    expect((await screen.findByRole("alert")).textContent).toContain("wrong file signature");
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(post?.[0]).toBe("/api/analyses");
    expect((post?.[1]?.body as FormData).get("file")).toBeInstanceOf(File);
  });
});
