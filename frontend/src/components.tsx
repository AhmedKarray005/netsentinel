// Small reusable building blocks shared by the pages.
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { Severity } from "./types";

export function Panel(props: { title: string; hint?: string; span?: 4 | 6 | 8 | 12; children: ReactNode }) {
  return (
    <section className={`panel span-${props.span ?? 12}`} aria-label={props.title}>
      <h2>{props.title}</h2>
      {props.hint && <p className="hint">{props.hint}</p>}
      {props.children}
    </section>
  );
}

export function StatTile(props: { label: string; value: string; sub?: ReactNode }) {
  return (
    <div className="tile">
      <div className="tile-label">{props.label}</div>
      <div className="tile-value">{props.value}</div>
      {props.sub && <div className="tile-sub">{props.sub}</div>}
    </div>
  );
}

const SEVERITY_ICON: Record<Severity, string> = { low: "i", medium: "!", high: "!!" };
const SEVERITY_LABEL: Record<Severity, string> = { low: "Low", medium: "Medium", high: "High" };

/** Severity is never shown by colour alone: icon + text label + colour. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className="badge">
      <span className={`badge-icon ${severity}`} aria-hidden="true">
        {SEVERITY_ICON[severity]}
      </span>
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function ErrorMessage({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="message error" role="alert">
      <strong>Error: </strong>
      {error}
    </div>
  );
}

export function NoAnalysis() {
  return (
    <div className="panel empty">
      <p>No capture analyzed yet.</p>
      <p>
        <Link to="/upload">Upload a PCAP file</Link> to see its traffic and alerts here.
      </p>
    </div>
  );
}

export function Pager(props: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  const { total, limit, offset, onChange } = props;
  if (total === 0) return null;
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <nav className="pager" aria-label="Pagination">
      <button disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
        Previous
      </button>
      <span>
        Page {page} of {pages} ({total} results)
      </span>
      <button disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>
        Next
      </button>
    </nav>
  );
}
