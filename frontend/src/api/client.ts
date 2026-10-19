import type {
  ApprovalResponse,
  HealthResponse,
  InvestigationResponse,
  ProblemDetail,
} from '../types';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

class ApiError extends Error {
  problem?: ProblemDetail;
  statusCode: number;

  constructor(message: string, statusCode: number, problem?: ProblemDetail) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.problem = problem;
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorData: any = null;
    try {
      errorData = await res.json();
    } catch {
      // not JSON
    }

    const problem: ProblemDetail | undefined = errorData?.detail;
    const msg =
      problem?.detail_template ||
      problem?.title ||
      errorData?.message ||
      `HTTP Request failed with status ${res.status}`;
    throw new ApiError(msg, res.status, problem);
  }
  return res.json() as Promise<T>;
}

export const api = {
  async getHealth(): Promise<HealthResponse> {
    const res = await fetch(`${BASE_URL}/health`);
    return handleResponse<HealthResponse>(res);
  },

  async uploadInvestigation(
    file: File,
    forceApproval = false
  ): Promise<InvestigationResponse> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('force_approval', String(forceApproval));

    const res = await fetch(`${BASE_URL}/api/v1/investigations`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse<InvestigationResponse>(res);
  },

  async getInvestigation(id: string): Promise<InvestigationResponse> {
    const res = await fetch(`${BASE_URL}/api/v1/investigations/${id}`);
    return handleResponse<InvestigationResponse>(res);
  },

  async downloadArtifact(id: string, artifactName: string): Promise<string> {
    const res = await fetch(
      `${BASE_URL}/api/v1/investigations/${id}/artifacts/${encodeURIComponent(artifactName)}`
    );
    if (!res.ok) {
      throw new Error(`Failed to download artifact '${artifactName}': HTTP ${res.status}`);
    }
    return res.text();
  },

  async submitApproval(
    id: string,
    decision: 'approved' | 'rejected',
    reason: string,
    operator = 'human_operator'
  ): Promise<ApprovalResponse> {
    const res = await fetch(`${BASE_URL}/api/v1/investigations/${id}/approval`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, reason, operator }),
    });
    return handleResponse<ApprovalResponse>(res);
  },

  async toggleKillSwitch(
    active: boolean,
    operator = 'admin'
  ): Promise<{ kill_switch_active: boolean; message: string }> {
    const res = await fetch(`${BASE_URL}/api/v1/kill-switch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active, operator }),
    });
    return handleResponse<{ kill_switch_active: boolean; message: string }>(res);
  },
};
