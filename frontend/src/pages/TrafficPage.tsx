import { useState } from "react";
import { api } from "../api";
import type { FlowFilters } from "../api";
import { ErrorMessage, NoAnalysis, Pager, Panel } from "../components";
import { endpoint, formatBytes, formatCount, formatDuration, formatOffset, formatTime } from "../format";
import { useAnalyses, useLoad } from "../state";
import type { Protocol, TcpState } from "../types";

const PROTOCOLS: Protocol[] = ["TCP", "UDP", "ICMP", "ICMPv6", "OTHER_IP"];
const STATES: TcpState[] = ["ESTABLISHED", "CLOSED", "REJECTED", "NO_REPLY", "HALF_OPEN", "MIDSTREAM"];
const PAGE_SIZE = 50;

interface FormState {
  protocol: Protocol | "";
  tcp_state: TcpState | "";
  ip: string;
  port: string;
  from: string; // seconds from capture start
  to: string;
  sort: "start" | "bytes" | "packets";
}

const EMPTY: FormState = { protocol: "", tcp_state: "", ip: "", port: "", from: "", to: "", sort: "start" };

export function TrafficPage() {
  const { selectedId, analyses, loading: listLoading } = useAnalyses();
  const analysis = analyses.find((a) => a.id === selectedId) ?? null;
  const captureStart = analysis?.start_time ?? null;

  const [form, setForm] = useState<FormState>(EMPTY);
  const [applied, setApplied] = useState<FormState>(EMPTY);
  const [offset, setOffset] = useState(0);

  const toFilters = (f: FormState): FlowFilters => ({
    protocol: f.protocol,
    tcp_state: f.tcp_state,
    ip: f.ip.trim(),
    port: f.port === "" ? "" : Number(f.port),
    since: f.from === "" || captureStart === null ? null : captureStart + Number(f.from),
    until: f.to === "" || captureStart === null ? null : captureStart + Number(f.to),
    sort: f.sort,
    limit: PAGE_SIZE,
    offset,
  });

  const flows = useLoad(
    () => (selectedId === null ? Promise.resolve(null) : api.listFlows(selectedId, toFilters(applied))),
    [selectedId, applied, offset],
  );

  if (!listLoading && selectedId === null) return <NoAnalysis />;

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }));
  const apply = (next: FormState) => {
    setApplied(next);
    setOffset(0);
  };

  return (
    <>
      <h1>Network traffic</h1>
      <p className="subtitle">
        Every conversation (flow) in <span className="mono">{analysis?.filename}</span>: who talked to
        whom, on which port, how much, and how the TCP connection ended.
      </p>

      <form
        className="filters"
        onSubmit={(e) => {
          e.preventDefault();
          apply(form);
        }}
      >
        <label className="field">
          Protocol
          <select value={form.protocol} onChange={(e) => set("protocol", e.target.value as FormState["protocol"])}>
            <option value="">All</option>
            {PROTOCOLS.map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
        </label>
        <label className="field">
          TCP state
          <select value={form.tcp_state} onChange={(e) => set("tcp_state", e.target.value as FormState["tcp_state"])}>
            <option value="">All</option>
            {STATES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <label className="field">
          IP address (either side)
          <input value={form.ip} onChange={(e) => set("ip", e.target.value)} placeholder="e.g. 192.168.1.13" />
        </label>
        <label className="field">
          Port (either side)
          <input type="number" min={0} max={65535} value={form.port} onChange={(e) => set("port", e.target.value)} />
        </label>
        <label className="field">
          From (s after start)
          <input type="number" min={0} step="any" value={form.from} onChange={(e) => set("from", e.target.value)} />
        </label>
        <label className="field">
          To (s after start)
          <input type="number" min={0} step="any" value={form.to} onChange={(e) => set("to", e.target.value)} />
        </label>
        <label className="field">
          Sort by
          <select value={form.sort} onChange={(e) => set("sort", e.target.value as FormState["sort"])}>
            <option value="start">Start time</option>
            <option value="bytes">Bytes (largest first)</option>
            <option value="packets">Packets (most first)</option>
          </select>
        </label>
        <button className="primary" type="submit">
          Apply
        </button>
        <button
          type="button"
          onClick={() => {
            setForm(EMPTY);
            apply(EMPTY);
          }}
        >
          Reset
        </button>
      </form>

      <ErrorMessage error={flows.error} />

      <div className="grid">
        <Panel
          title="Flows"
          hint="→ = client to server (the side that spoke first), ← = replies. Time is relative to the capture start."
        >
          <div className="table-wrap">
            <table>
              <caption>
                {flows.loading ? "Loading…" : `${formatCount(flows.data?.total ?? 0)} matching flows`}
              </caption>
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Client</th>
                  <th>Server</th>
                  <th>Start</th>
                  <th className="num">Duration</th>
                  <th className="num">Packets → / ←</th>
                  <th className="num">Bytes</th>
                  <th>TCP state</th>
                </tr>
              </thead>
              <tbody>
                {flows.data?.items.map((f) => (
                  <tr key={f.id}>
                    <td>{f.protocol}</td>
                    <td className="mono">{endpoint(f.client_ip, f.client_port)}</td>
                    <td className="mono">{endpoint(f.server_ip, f.server_port)}</td>
                    <td title={formatTime(f.start)}>{formatOffset(f.start, captureStart)}</td>
                    <td className="num">{formatDuration(f.duration_seconds)}</td>
                    <td className="num">
                      {formatCount(f.packets_fwd)} / {formatCount(f.packets_bwd)}
                    </td>
                    <td className="num">{formatBytes(f.bytes_total)}</td>
                    <td>{f.tcp_state && <span className="state">{f.tcp_state}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {flows.data && flows.data.total === 0 && <p className="empty">No flow matches these filters.</p>}
          </div>
          {flows.data && (
            <Pager total={flows.data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
          )}
        </Panel>
      </div>
    </>
  );
}
