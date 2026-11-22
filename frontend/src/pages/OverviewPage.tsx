import { Link } from "react-router-dom";
import { api } from "../api";
import { BarList, TimelineChart, recordToBars } from "../charts";
import { ErrorMessage, NoAnalysis, Panel, SeverityBadge, StatTile } from "../components";
import {
  fillTimeline,
  formatBytes,
  formatCount,
  formatDuration,
  formatTime,
} from "../format";
import { useAnalyses, useLoad } from "../state";
import type { Severity } from "../types";

const SEVERITIES: Severity[] = ["high", "medium", "low"];

export function OverviewPage() {
  const { selectedId, loading: listLoading } = useAnalyses();
  const detail = useLoad(
    () => (selectedId === null ? Promise.resolve(null) : api.getAnalysis(selectedId)),
    [selectedId],
  );
  const alerts = useLoad(
    () =>
      selectedId === null
        ? Promise.resolve(null)
        : api.listAlerts({ analysis_id: selectedId, limit: 5 }),
    [selectedId],
  );

  if (!listLoading && selectedId === null) return <NoAnalysis />;
  const a = detail.data;
  if (!a) return <ErrorMessage error={detail.error} />;

  const s = a.overview.summary;
  const f = a.overview.flows;
  const points = fillTimeline(s.timeline.buckets, s.timeline.bucket_seconds);

  return (
    <>
      <h1>Overview</h1>
      <p className="subtitle">
        <span className="mono">{a.filename}</span> · {formatTime(a.start_time)} →{" "}
        {formatTime(a.end_time)} ({formatDuration(a.duration_seconds)})
      </p>
      <ErrorMessage error={detail.error} />

      <div className="tiles">
        <StatTile
          label="Packets analyzed"
          value={formatCount(a.packet_count)}
          sub={formatBytes(s.total_bytes)}
        />
        <StatTile
          label="Flows"
          value={formatCount(a.flow_count)}
          sub={recordToBars(f.by_protocol, 3)
            .map((b) => `${b.label} ${formatCount(b.value)}`)
            .join(" · ")}
        />
        <StatTile
          label="Average rate"
          value={s.packets_per_second === null ? "–" : `${formatCount(Math.round(s.packets_per_second))}/s`}
          sub={
            s.timeline.peak
              ? `peak ${formatCount(s.timeline.peak.packets)} packets in ${s.timeline.bucket_seconds} s`
              : undefined
          }
        />
        <StatTile
          label="Security alerts"
          value={formatCount(a.alert_count)}
          sub={
            a.alert_count === 0
              ? "no rule threshold reached"
              : SEVERITIES.filter((sev) => a.alerts_by_severity[sev])
                  .map((sev) => `${a.alerts_by_severity[sev]} ${sev}`)
                  .join(" · ")
          }
        />
      </div>

      <div className="grid">
        <Panel
          title="Traffic over time"
          hint={`Packets per ${s.timeline.bucket_seconds} s interval, from the start of the capture`}
          span={8}
        >
          <TimelineChart
            points={points}
            captureStart={a.start_time}
            bucketSeconds={s.timeline.bucket_seconds}
          />
        </Panel>

        <Panel title="Protocol distribution" hint="Packets per protocol" span={4}>
          <BarList items={recordToBars(s.protocols)} />
        </Panel>

        <Panel title="Latest alerts" hint="Indicators to investigate, not proof of an attack" span={6}>
          <ErrorMessage error={alerts.error} />
          {alerts.data && alerts.data.items.length === 0 && (
            <p className="empty">No alert for this capture.</p>
          )}
          {alerts.data && alerts.data.items.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Source</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.data.items.map((al) => (
                    <tr key={al.id}>
                      <td>
                        <SeverityBadge severity={al.severity} />
                      </td>
                      <td>
                        {al.rule_id} {al.rule_name}
                      </td>
                      <td className="mono">{al.src_ip}</td>
                      <td>{formatTime(al.start)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p>
                <Link to="/alerts">All alerts and evidence →</Link>
              </p>
            </div>
          )}
        </Panel>

        <Panel title="TCP connection states" hint="How each TCP conversation went" span={6}>
          <BarList items={recordToBars(f.tcp_states)} emptyText="No TCP traffic" />
        </Panel>

        <Panel title="Most active hosts" hint="Bytes sent + received across all their flows" span={6}>
          <BarList
            format={formatBytes}
            items={f.top_talkers.slice(0, 8).map((t) => ({
              label: t.host,
              value: t.bytes,
              title: `${t.host}: sent ${formatBytes(t.bytes_sent)}, received ${formatBytes(t.bytes_received)}`,
            }))}
          />
        </Panel>

        <Panel
          title="Top destination ports"
          hint="Packets per protocol/port, both directions (replies go to the client's temporary port)"
          span={6}
        >
          <BarList items={recordToBars(s.top_dst_ports, 8)} />
        </Panel>

        <Panel title="Top conversations" hint="Host pairs, all ports together" span={12}>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Host A</th>
                  <th>Host B</th>
                  <th className="num">Flows</th>
                  <th className="num">Packets</th>
                  <th className="num">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {f.top_conversations.map((c) => (
                  <tr key={c.hosts.join("|")}>
                    <td className="mono">{c.hosts[0]}</td>
                    <td className="mono">{c.hosts[1]}</td>
                    <td className="num">{formatCount(c.flows)}</td>
                    <td className="num">{formatCount(c.packets)}</td>
                    <td className="num">{formatBytes(c.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        {Object.keys(s.top_dns_queries).length > 0 && (
          <Panel title="Top DNS queries" hint="Names asked by hosts in this capture" span={12}>
            <BarList items={recordToBars(s.top_dns_queries)} />
          </Panel>
        )}
      </div>
    </>
  );
}
