import { useState } from "react";
import { api } from "../api";
import { ErrorMessage, Pager, SeverityBadge } from "../components";
import { endpoint, formatTime } from "../format";
import { useAnalyses, useLoad } from "../state";
import type { Alert, Severity } from "../types";

const PAGE_SIZE = 20;

function KeyValues({ data }: { data: Record<string, unknown> }) {
  return (
    <dl className="kv">
      {Object.entries(data).map(([key, value]) => (
        <div key={key} style={{ display: "contents" }}>
          <dt>{key.replaceAll("_", " ")}</dt>
          <dd className="mono">
            {Array.isArray(value)
              ? value.join(", ")
              : typeof value === "object" && value !== null
                ? Object.entries(value)
                    .map(([k, v]) => `${k}: ${String(v)}`)
                    .join(", ")
                : String(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function AlertCard({ alert }: { alert: Alert }) {
  const target = alert.dst_ip ? endpoint(alert.dst_ip, alert.dst_port) : "many hosts";
  return (
    <details className="alert-card">
      <summary>
        <div className="alert-head">
          <SeverityBadge severity={alert.severity} />
          <span className="alert-rule">
            {alert.rule_id} · {alert.rule_name}
          </span>
          <span className="alert-meta">{formatTime(alert.start)}</span>
        </div>
        <div>{alert.summary}</div>
        <div className="alert-meta">
          <span className="mono">{alert.src_ip}</span> → <span className="mono">{target}</span> · analysis #
          {alert.analysis_id} · click for evidence
        </div>
      </summary>
      <div className="alert-body">
        <div>
          <h3>Evidence</h3>
          <KeyValues data={alert.evidence} />
        </div>
        <div>
          <h3>Why it fired</h3>
          <KeyValues
            data={{
              ...alert.thresholds,
              mitre_attack: alert.mitre_attack,
              first_seen: formatTime(alert.start),
              last_seen: formatTime(alert.end),
            }}
          />
          <p className="alert-meta">
            An alert is an indicator worth checking, not proof of an attack. See docs/detection.md for
            known false positives.
          </p>
        </div>
      </div>
    </details>
  );
}

export function AlertsPage() {
  const { selectedId } = useAnalyses();
  const [scope, setScope] = useState<"selected" | "all">("selected");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [ruleId, setRuleId] = useState("");
  const [offset, setOffset] = useState(0);

  const rules = useLoad(() => api.rules(), []);
  const analysisId = scope === "selected" ? selectedId : null;
  const alerts = useLoad(
    () =>
      scope === "selected" && selectedId === null
        ? Promise.resolve(null)
        : api.listAlerts({ analysis_id: analysisId, severity, rule_id: ruleId, limit: PAGE_SIZE, offset }),
    [analysisId, scope, severity, ruleId, offset],
  );

  const resetPage = <T,>(setter: (v: T) => void) => (v: T) => {
    setter(v);
    setOffset(0);
  };

  return (
    <>
      <h1>Security alerts</h1>
      <p className="subtitle">
        Suspicious patterns found by NetSentinel's rules. Open an alert to see the numbers behind it.
      </p>

      <div className="filters">
        <label className="field">
          Captures
          <select value={scope} onChange={(e) => resetPage(setScope)(e.target.value as "selected" | "all")}>
            <option value="selected">Selected capture</option>
            <option value="all">All captures</option>
          </select>
        </label>
        <label className="field">
          Severity
          <select value={severity} onChange={(e) => resetPage(setSeverity)(e.target.value as Severity | "")}>
            <option value="">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
        <label className="field">
          Rule
          <select value={ruleId} onChange={(e) => resetPage(setRuleId)(e.target.value)}>
            <option value="">All</option>
            {rules.data?.map((r) => (
              <option key={r.rule_id} value={r.rule_id}>
                {r.rule_id} {r.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      <ErrorMessage error={alerts.error} />
      {alerts.data && alerts.data.total === 0 && (
        <div className="panel empty">No alert matches. No rule threshold was reached for these captures.</div>
      )}
      {alerts.data?.items.map((alert) => <AlertCard key={alert.id} alert={alert} />)}
      {alerts.data && <Pager total={alerts.data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />}

      {rules.data && (
        <section className="panel" style={{ marginTop: 24 }} aria-label="Detection rules">
          <h2>Detection rules</h2>
          <p className="hint">Current thresholds used by the server</p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>What it looks for</th>
                  <th>MITRE ATT&amp;CK</th>
                  <th>Thresholds</th>
                </tr>
              </thead>
              <tbody>
                {rules.data.map((r) => (
                  <tr key={r.rule_id}>
                    <td>
                      {r.rule_id} {r.name} {!r.enabled && "(disabled)"}
                    </td>
                    <td style={{ whiteSpace: "normal", minWidth: 260 }}>{r.description}</td>
                    <td>{r.mitre_attack}</td>
                    <td className="mono" style={{ whiteSpace: "normal" }}>
                      {Object.entries(r.thresholds)
                        .map(([k, v]) => `${k}=${String(v)}`)
                        .join(", ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );
}
