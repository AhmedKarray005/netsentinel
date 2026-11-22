import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../api";
import { ErrorMessage, Panel } from "../components";
import { formatBytes, formatCount, formatDuration } from "../format";
import { useAnalyses } from "../state";
import type { AnalysisDetail } from "../types";

/** Turn API status codes into advice the user can act on. */
export function uploadErrorText(error: unknown): string {
  if (!(error instanceof ApiError)) return String(error);
  switch (error.status) {
    case 0:
      return error.message;
    case 413:
      return "The file is larger than the server's upload limit (NETSENTINEL_MAX_UPLOAD_MB).";
    case 415:
      return "Only .pcap, .pcapng and .cap capture files are accepted.";
    case 422:
      return `The file was rejected: ${error.message}. Save it from Wireshark as pcap or pcapng.`;
    default:
      return `Upload failed (${error.status}): ${error.message}`;
  }
}

export function UploadPage() {
  const { analyses, select, refresh, selectedId } = useAnalyses();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisDetail | null>(null);

  async function upload() {
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    const started = performance.now();
    try {
      const analysis = await api.uploadCapture(file);
      setResult(analysis);
      select(analysis.id);
      await refresh();
      if (input.current) input.current.value = "";
      setFile(null);
      console.info(`analysis ${analysis.id} done in ${Math.round(performance.now() - started)} ms`);
    } catch (e) {
      setError(uploadErrorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: number, name: string) {
    if (!window.confirm(`Delete analysis #${id} (${name}) with all its flows and alerts?`)) return;
    try {
      await api.deleteAnalysis(id);
      if (result?.id === id) setResult(null);
      await refresh();
    } catch (e) {
      setError(uploadErrorText(e));
    }
  }

  return (
    <>
      <h1>Analyze a capture</h1>
      <p className="subtitle">
        Upload a PCAP/PCAPNG file you are allowed to inspect (your own lab traffic). The raw file is
        deleted after analysis; only metadata is kept.
      </p>

      <div className="grid">
        <Panel title="Upload" span={6}>
          <form
            className="filters"
            onSubmit={(e) => {
              e.preventDefault();
              void upload();
            }}
          >
            <label className="field">
              Capture file
              <input
                ref={input}
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </label>
            <button className="primary" type="submit" disabled={!file || busy}>
              {busy ? "Analyzing…" : "Upload and analyze"}
            </button>
          </form>
          {file && !busy && <p className="hint">Selected: {file.name} ({formatBytes(file.size)})</p>}
          <ErrorMessage error={error} />
          {result && (
            <div className="message ok" role="status">
              <strong>Analysis #{result.id} done.</strong> {formatCount(result.packet_count)} packets,{" "}
              {formatCount(result.flow_count)} flows, {formatCount(result.alert_count)} alert(s).{" "}
              <Link to="/">Open the overview →</Link>
            </div>
          )}
        </Panel>

        <Panel title="How to get a capture" span={6}>
          <ol>
            <li>Wireshark → Capture → Options → pick an interface (Wi-Fi, or loopback for 127.0.0.1).</li>
            <li>Generate the traffic you want to study, then stop the capture (red square).</li>
            <li>File → Save As → pcapng.</li>
          </ol>
          <p className="hint">
            Lab traffic generator: <span className="mono">python lab/scenarios/loopback_test.py scan</span>
          </p>
        </Panel>

        <Panel title="Analyzed captures" span={12}>
          {analyses.length === 0 ? (
            <p className="empty">Nothing yet.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>File</th>
                    <th>Analyzed at</th>
                    <th className="num">Size</th>
                    <th className="num">Duration</th>
                    <th className="num">Packets</th>
                    <th className="num">Flows</th>
                    <th className="num">Alerts</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {analyses.map((a) => (
                    <tr key={a.id}>
                      <td>{a.id}</td>
                      <td className="mono">
                        {a.filename} {a.id === selectedId && <span className="state">selected</span>}
                      </td>
                      <td>{a.created_at.replace("T", " ").slice(0, 19)}</td>
                      <td className="num">{formatBytes(a.size_bytes)}</td>
                      <td className="num">{formatDuration(a.duration_seconds)}</td>
                      <td className="num">{formatCount(a.packet_count)}</td>
                      <td className="num">{formatCount(a.flow_count)}</td>
                      <td className="num">{formatCount(a.alert_count)}</td>
                      <td>
                        <button type="button" onClick={() => select(a.id)}>
                          Select
                        </button>{" "}
                        <button type="button" className="danger" onClick={() => void remove(a.id, a.filename)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
