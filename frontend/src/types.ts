export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type PolicyOutcome = 'allow' | 'require_approval' | 'deny' | 'denied_by_operator';

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  evidence_ids: string[];
  attack_technique_id: string | null;
  cwe_id: string | null;
  created_at: string;
}

export interface EventSample {
  line_number: number;
  timestamp: string;
  source: string;
  event_type: string;
  raw_line: string;
}

export interface ApprovalActionDetail {
  proposal_id: string;
  tool_id: string;
  target: string;
  params: Record<string, unknown>;
  risk_class: string;
  lab_only: boolean;
  reason: string;
  evidence_rationale: string;
  status: 'pending' | 'approved' | 'rejected';
  policy_decision?: string;
  execution_output?: string;
  operator_reason?: string;
}

export interface InvestigationResponse {
  investigation_id: string;
  title: string;
  status: string;
  created_at: string;
  created_by: string;
  filename: string;
  file_bytes: number;
  is_demo_mode: boolean;
  model_name: string;
  proposed_severity: Severity;
  severity_rationale: string;
  executive_summary: string;
  policy_outcome: PolicyOutcome;
  action_risk_summary: string;
  suspected_injection: boolean;
  findings_count: number;
  findings: Finding[];
  events_count: number;
  events_sample: EventSample[];
  candidate_indicators: {
    ips: string[];
    domains: string[];
    sha256: string[];
    sha1: string[];
    md5: string[];
    attack_techniques: string[];
  };
  unique_sources: string[];
  unique_ips: string[];
  unique_users: string[];
  unique_hosts: string[];
  uncertainties: string[];
  defensive_actions: string[];
  approval_required: boolean;
  approval_action_detail: ApprovalActionDetail | null;
  available_artifacts: string[];
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  config_sha256: string;
  demo_mode: boolean;
  kill_switch_active: boolean;
  active_investigations: number;
}

export interface ApprovalResponse {
  status: 'approved' | 'rejected';
  policy_decision?: string;
  execution_result?: string;
  investigation_id: string;
  message?: string;
}

export interface ProblemDetail {
  type: string;
  title: string;
  status: number;
  code: string;
  detail_template: string;
  next_step_template: string;
  instance?: string | null;
}
