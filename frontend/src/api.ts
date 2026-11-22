// The only file that talks to the backend. Pages call these functions, never fetch() directly.
import type {
  Alert,
  Analysis,
  AnalysisDetail,
  Flow,
  Page,
  Protocol,
  RuleInfo,
  Severity,
  TcpState,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

type QueryValue = string | number | null | undefined;

/** Build "?a=1&b=x", skipping empty values so the API sees only real filters. */
export function queryString(params: Record<string, QueryValue>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === "") continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

/** FastAPI errors are {"detail": "text"} or {"detail": [{"msg": ...}, ...]} (validation). */
export function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((d) => (d && typeof d === "object" && "msg" in d ? String(d.msg) : String(d)))
        .join("; ");
    }
  }
  return fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/api${path}`, init);
  } catch {
    throw new ApiError(0, "Cannot reach the NetSentinel API. Is `netsentinel serve` running?");
  }
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      /* not JSON: keep the status text */
    }
    throw new ApiError(response.status, errorMessage(body, response.statusText || "Request failed"));
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export interface FlowFilters {
  protocol?: Protocol | "";
  tcp_state?: TcpState | "";
  ip?: string;
  port?: number | "";
  since?: number | null;
  until?: number | null;
  sort?: "start" | "bytes" | "packets";
  limit?: number;
  offset?: number;
}

export interface AlertFilters {
  analysis_id?: number | null;
  severity?: Severity | "";
  rule_id?: string;
  ip?: string;
  limit?: number;
  offset?: number;
}

export const api = {
  health: () => request<{ status: string; version: string }>("/health"),
  rules: () => request<RuleInfo[]>("/rules"),
  listAnalyses: (limit = 50, offset = 0) =>
    request<Page<Analysis>>(`/analyses${queryString({ limit, offset })}`),
  getAnalysis: (id: number) => request<AnalysisDetail>(`/analyses/${id}`),
  deleteAnalysis: (id: number) => request<void>(`/analyses/${id}`, { method: "DELETE" }),
  uploadCapture: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<AnalysisDetail>("/analyses", { method: "POST", body: form });
  },
  listFlows: (analysisId: number, filters: FlowFilters) =>
    request<Page<Flow>>(`/analyses/${analysisId}/flows${queryString({ ...filters })}`),
  listAlerts: (filters: AlertFilters) =>
    request<Page<Alert>>(`/alerts${queryString({ ...filters })}`),
};
