// TypeScript shapes of the JSON returned by the NetSentinel API (see docs/api.md).
// TypeScript checks at build time that the code only uses fields that exist.

export type Severity = "low" | "medium" | "high";
export type Protocol = "TCP" | "UDP" | "ICMP" | "ICMPv6" | "OTHER_IP";
export type TcpState =
  | "ESTABLISHED"
  | "CLOSED"
  | "REJECTED"
  | "NO_REPLY"
  | "HALF_OPEN"
  | "MIDSTREAM";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Analysis {
  id: number;
  filename: string;
  sha256: string;
  size_bytes: number;
  created_at: string;
  packet_count: number;
  flow_count: number;
  alert_count: number;
  start_time: number | null;
  end_time: number | null;
  duration_seconds: number;
}

export interface TimelineBucket {
  start: number;
  packets: number;
  bytes: number;
}

export interface PacketSummary {
  packet_count: number;
  total_bytes: number;
  start_time: string | null;
  end_time: string | null;
  duration_seconds: number;
  packets_per_second: number | null;
  packet_length: { min: number | null; max: number | null; mean: number };
  protocols: Record<string, number>;
  top_src_ips: Record<string, number>;
  top_dst_ips: Record<string, number>;
  top_dst_ports: Record<string, number>;
  top_dns_queries: Record<string, number>;
  timeline: {
    bucket_seconds: number;
    peak: { start: string; packets: number } | null;
    buckets: TimelineBucket[];
  };
}

export interface Talker {
  host: string;
  bytes_sent: number;
  bytes_received: number;
  bytes: number;
}

export interface Conversation {
  hosts: string[];
  flows: number;
  packets: number;
  bytes: number;
}

export interface FlowReport {
  flow_count: number;
  by_protocol: Record<string, number>;
  tcp_states: Record<string, number>;
  top_conversations: Conversation[];
  top_talkers: Talker[];
}

export interface AnalysisDetail extends Analysis {
  overview: { summary: PacketSummary; flows: FlowReport };
  alerts_by_severity: Partial<Record<Severity, number>>;
}

export interface Flow {
  id: number;
  analysis_id: number;
  protocol: string;
  client_ip: string;
  client_port: number | null;
  server_ip: string;
  server_port: number | null;
  start: number;
  end: number;
  duration_seconds: number;
  packets_fwd: number;
  packets_bwd: number;
  bytes_fwd: number;
  bytes_bwd: number;
  bytes_total: number;
  tcp_state: string | null;
}

export interface Alert {
  id: number;
  analysis_id: number;
  rule_id: string;
  rule_name: string;
  mitre_attack: string;
  severity: Severity;
  start: number;
  end: number;
  start_iso: string;
  src_ip: string;
  dst_ip: string | null;
  dst_port: number | null;
  summary: string;
  thresholds: Record<string, unknown>;
  evidence: Record<string, unknown>;
}

export interface RuleInfo {
  rule_id: string;
  name: string;
  description: string;
  mitre_attack: string;
  enabled: boolean;
  thresholds: Record<string, unknown>;
}
