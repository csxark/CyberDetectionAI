import React, { useState, useEffect, useRef } from 'react';
import { api } from './api/client';
import type {
  InvestigationResponse,
  HealthResponse,
  Finding,
  EventSample,
} from './types';

export function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [forceApproval, setForceApproval] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'evidence' | 'artifacts'>('findings');
  const [viewingArtifact, setViewingArtifact] = useState<{ name: string; content: string } | null>(null);
  const [approvalLoading, setApprovalLoading] = useState<boolean>(false);
  const [approvalReason, setApprovalReason] = useState<string>('Operator verified brute-force pattern');

  const fileInputRef = useRef<HTMLInputElement>(null);


  // Poll backend health on mount
  useEffect(() => {
    let active = true;
    const fetchHealth = async () => {
      try {
        const h = await api.getHealth();
        if (active) setHealth(h);
      } catch {
        if (active) setHealth(null);
      }
    };
    void fetchHealth();
    const interval = setInterval(() => {
      void fetchHealth();
    }, 10000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  async function handleToggleKillSwitch() {
    if (!health) return;
    try {
      const res = await api.toggleKillSwitch(!health.kill_switch_active, 'console_operator');
      setHealth((prev) => (prev ? { ...prev, kill_switch_active: res.kill_switch_active } : null));
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to toggle kill switch.');
    }
  }

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setErrorMsg(null);
    }
  }

  function loadSampleLog(type: 'brute' | 'web' | 'jsonl') {
    let filename = 'sample_auth.log';
    let content = '';

    if (type === 'brute') {
      filename = 'auth_bruteforce.log';
      content = `Oct 18 10:14:01 prod-web-01 sshd[2841]: Failed password for invalid user admin from 198.51.100.22 port 44821 ssh2
Oct 18 10:14:04 prod-web-01 sshd[2845]: Failed password for invalid user admin from 198.51.100.22 port 44825 ssh2
Oct 18 10:14:08 prod-web-01 sshd[2850]: Failed password for invalid user admin from 198.51.100.22 port 44830 ssh2
Oct 18 10:14:12 prod-web-01 sshd[2854]: Failed password for invalid user admin from 198.51.100.22 port 44835 ssh2
Oct 18 10:14:16 prod-web-01 sshd[2860]: Accepted password for root from 198.51.100.22 port 44840 ssh2
Oct 18 10:14:20 prod-web-01 sudo[2870]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash`;
    } else if (type === 'web') {
      filename = 'web_access.log';
      content = `2026-10-18T11:00:01Z gateway-01 nginx: 203.0.113.88 - - "GET /index.html HTTP/1.1" 200 1420
2026-10-18T11:00:05Z gateway-01 nginx: 203.0.113.88 - - "GET /../../etc/passwd HTTP/1.1" 400 182
2026-10-18T11:00:10Z gateway-01 nginx: 203.0.113.88 - - "GET /search?q=1%27+UNION+SELECT+1,table_name+FROM+information_schema.tables-- HTTP/1.1" 500 234`;
    } else {
      filename = 'cloud_telemetry.jsonl';
      content = `{"timestamp": "2026-10-18T12:00:00Z", "source": "aws.cloudtrail", "user": "dev-user", "event": "DescribeInstances", "src_ip": "10.0.0.15"}
{"timestamp": "2026-10-18T12:05:00Z", "source": "aws.cloudtrail", "user": "dev-user", "event": "CreateAccessKey", "src_ip": "198.51.100.75"}
{"timestamp": "2026-10-18T12:06:00Z", "source": "aws.cloudtrail", "user": "dev-user", "event": "Technique T1078 valid account abuse", "src_ip": "198.51.100.75"}`;
    }

    const file = new File([content], filename, { type: 'text/plain' });
    setSelectedFile(file);
    setErrorMsg(null);
  }

  async function handleAnalyze() {
    if (!selectedFile) {
      setErrorMsg('Please select a local log file to analyze.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setViewingArtifact(null);

    try {
      const resp = await api.uploadInvestigation(selectedFile, forceApproval);
      setInvestigation(resp);
      setActiveTab('findings');
    } catch (err: any) {
      setErrorMsg(err.message || 'Investigation failed to process.');
    } finally {
      setLoading(false);
    }
  }

  async function handleLoadArtifact(name: string) {
    if (!investigation) return;
    try {
      const content = await api.downloadArtifact(investigation.investigation_id, name);
      setViewingArtifact({ name, content });
    } catch (err: any) {
      setErrorMsg(err.message || `Failed to download artifact '${name}'.`);
    }
  }

  function handleDownloadFile(name: string, content: string) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
    URL.revokeObjectURL(url);
  }

  async function handleApprovalDecision(decision: 'approved' | 'rejected') {
    if (!investigation) return;
    setApprovalLoading(true);
    try {
      await api.submitApproval(
        investigation.investigation_id,
        decision,
        approvalReason,
        'operator_alice'
      );
      // Refresh current investigation state
      const updated = await api.getInvestigation(investigation.investigation_id);
      setInvestigation(updated);
    } catch (err: any) {
      setErrorMsg(err.message || 'Approval decision recording failed.');
    } finally {
      setApprovalLoading(false);
    }
  }

  return (
    <div className="container">
      {/* Header */}
      <header className="header">
        <div className="header-brand">
          <svg className="shield-icon" viewBox="0 0 24 24">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.47-3.08 8.66-7 9.8-3.92-1.14-7-5.33-7-9.8V6.3l7-3.12zM11 7v6h2V7h-2zm0 8v2h2v-2h-2z" />
          </svg>
          <div>
            <h1 className="header-title">SentinelAI</h1>
            <p className="header-subtitle">
              Safety-First Cybersecurity Investigation Assistant
            </p>
          </div>
        </div>

        <div className="header-meta">
          {health ? (
            <>
              <span className={`badge ${health.demo_mode ? 'badge-demo' : 'badge-live'}`}>
                {health.demo_mode ? 'Demo Mode (Offline)' : 'Mistral Large (Live)'}
              </span>
              <button
                className={`btn btn-sm ${health.kill_switch_active ? 'btn-danger' : 'btn-secondary'}`}
                onClick={handleToggleKillSwitch}
                title="Emergency Kill Switch (INV-12)"
              >
                {health.kill_switch_active ? '🚨 Kill Switch Active' : 'Kill Switch: Normal'}
              </button>
            </>
          ) : (
            <span className="badge badge-deny">Backend Offline</span>
          )}
        </div>
      </header>

      {/* Kill Switch Banner if Active */}
      {health?.kill_switch_active && (
        <div className="alert alert-danger">
          <strong>🚨 Execution Kill Switch Engaged:</strong> All model actions, tool executions,
          and new investigations are blocked by operator policy. Disengage kill switch above to resume.
        </div>
      )}

      {/* Error Banner */}
      {errorMsg && (
        <div className="alert alert-danger">
          <strong>Error:</strong> {errorMsg}
        </div>
      )}

      {/* Screen A: Investigation Ingest Card */}
      <section className="card">
        <div className="card-title">
          <span>Security Log Upload</span>
          <span className="sample-label">Formats: .log, .txt, .json, .jsonl, .csv (Max: 5MB)</span>
        </div>

        <div
          className="dropzone"
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileSelect}
            style={{ display: 'none' }}
            accept=".log,.txt,.json,.jsonl,.csv"
          />
          <p className="dropzone-text">
            {selectedFile ? (
              <strong>{selectedFile.name}</strong>
            ) : (
              'Click or drag a security log file here to analyze'
            )}
          </p>
          <p className="dropzone-hint">
            Deterministic parsing with untrusted evidence boundary (INV-7) & prompt injection guard
          </p>
          {selectedFile && (
            <div className="file-pill">
              <span>📄 {selectedFile.name}</span>
              <span>•</span>
              <span>{(selectedFile.size / 1024).toFixed(1)} KB</span>
            </div>
          )}
        </div>

        {/* Quick Sample Log Loaders for convenient testing */}
        <div className="sample-bar">
          <span className="sample-label">Quick Test Fixtures:</span>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => loadSampleLog('brute')}
          >
            SSH Brute Force (.log)
          </button>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => loadSampleLog('web')}
          >
            Web Traversal / SQLi (.log)
          </button>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => loadSampleLog('jsonl')}
          >
            Cloud Telemetry (.jsonl)
          </button>
        </div>

        <div style={{ marginTop: '1.25rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={forceApproval}
              onChange={(e) => setForceApproval(e.target.checked)}
            />
            <span>Test Human Approval Gate (propose lab_block_ip response action)</span>
          </label>

          <button
            className="btn btn-primary"
            onClick={handleAnalyze}
            disabled={!selectedFile || loading}
          >
            {loading && <div className="spinner" />}
            {loading ? 'Analyzing Evidence...' : 'Start Safety-Governed Investigation'}
          </button>
        </div>
      </section>

      {/* Screen B & C: Investigation Results and Response Workflow */}
      {investigation && (
        <>
          {/* Executive Summary & Severity Card */}
          <section className="card">
            <div className="card-title">
              <div>
                <span>Investigation Results</span>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-dim)', marginLeft: '0.75rem' }}>
                  ID: {investigation.investigation_id}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <span className={`badge badge-${investigation.proposed_severity}`}>
                  Severity: {investigation.proposed_severity}
                </span>
                <span className={`badge badge-${investigation.policy_outcome}`}>
                  Policy: {investigation.policy_outcome}
                </span>
              </div>
            </div>

            {/* Critical Principle Callout */}
            <div className="alert alert-info" style={{ marginBottom: '1.25rem' }}>
              <strong>Architectural Principle:</strong> Incident severity (<code>{investigation.proposed_severity.toUpperCase()}</code>) is decoupled from action authorization (<code>{investigation.policy_outcome.toUpperCase()}</code>). Tool execution is strictly governed by the server-side Policy Engine.
            </div>

            <p style={{ fontSize: '0.95rem', color: 'var(--text-main)', marginBottom: '1.25rem' }}>
              {investigation.executive_summary}
            </p>

            <div className="stat-grid">
              <div className="stat-box">
                <div className="stat-label">Events Parsed</div>
                <div className="stat-value">{investigation.events_count}</div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Security Findings</div>
                <div className="stat-value">{investigation.findings_count}</div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Unique IPs</div>
                <div className="stat-value">{investigation.unique_ips.length}</div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Sources / Hosts</div>
                <div className="stat-value">{investigation.unique_sources.length}</div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Action Risk</div>
                <div className="stat-value" style={{ fontSize: '0.9rem', color: 'var(--text-muted)', fontWeight: 500 }}>
                  {investigation.action_risk_summary}
                </div>
              </div>
            </div>

            {/* Screen C: Human Approval Gate if Required */}
            {investigation.approval_required && investigation.approval_action_detail && (
              <div className="alert alert-warning" style={{ display: 'block', border: '1px solid #d97706' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <strong style={{ fontSize: '1rem', color: '#fde68a' }}>
                    🛡️ Human Operator Approval Required (Path B)
                  </strong>
                  <span className={`badge badge-${investigation.approval_action_detail.status}`}>
                    {investigation.approval_action_detail.status.toUpperCase()}
                  </span>
                </div>
                <p style={{ fontSize: '0.85rem', marginBottom: '0.75rem', color: '#fcd34d' }}>
                  The agent proposed a candidate response action (<strong>{investigation.approval_action_detail.tool_id}</strong>) targeting <strong>{investigation.approval_action_detail.target}</strong>. Under policy, this action is paused until authorized by a human operator.
                </p>

                {investigation.approval_action_detail.status === 'pending' ? (
                  <div>
                    <div style={{ marginBottom: '0.75rem' }}>
                      <input
                        type="text"
                        style={{
                          width: '100%',
                          background: '#1e293b',
                          border: '1px solid #334155',
                          borderRadius: '4px',
                          padding: '0.5rem',
                          color: '#fff',
                          fontSize: '0.85rem',
                        }}
                        value={approvalReason}
                        onChange={(e) => setApprovalReason(e.target.value)}
                        placeholder="Operator justification note..."
                      />
                    </div>
                    <div style={{ display: 'flex', gap: '0.75rem' }}>
                      <button
                        className="btn btn-success btn-sm"
                        onClick={() => handleApprovalDecision('approved')}
                        disabled={approvalLoading}
                      >
                        {approvalLoading ? 'Evaluating Policy...' : 'Approve Action (Lab Simulation)'}
                      </button>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleApprovalDecision('rejected')}
                        disabled={approvalLoading}
                      >
                        Reject Action
                      </button>
                    </div>
                  </div>
                ) : (
                  <div style={{ fontSize: '0.85rem', background: 'rgba(0,0,0,0.2)', padding: '0.5rem', borderRadius: '4px' }}>
                    <div>Operator Status: <strong>{investigation.approval_action_detail.status}</strong></div>
                    {investigation.approval_action_detail.policy_decision && (
                      <div>Policy Decision: <strong>{investigation.approval_action_detail.policy_decision}</strong></div>
                    )}
                    {investigation.approval_action_detail.execution_output && (
                      <div style={{ marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
                        {investigation.approval_action_detail.execution_output}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Interactive Results Tabs */}
          <div className="tabs">
            <button
              className={`tab-btn ${activeTab === 'findings' ? 'active' : ''}`}
              onClick={() => setActiveTab('findings')}
            >
              Security Findings ({investigation.findings.length})
            </button>
            <button
              className={`tab-btn ${activeTab === 'evidence' ? 'active' : ''}`}
              onClick={() => setActiveTab('evidence')}
            >
              Evidence & Telemetry ({investigation.events_count})
            </button>
            <button
              className={`tab-btn ${activeTab === 'artifacts' ? 'active' : ''}`}
              onClick={() => setActiveTab('artifacts')}
            >
              Response Artifacts ({investigation.available_artifacts.length})
            </button>
          </div>

          {/* Tab 1: Findings */}
          {activeTab === 'findings' && (
            <section className="card">
              <div className="card-title">
                <span>Correlated Findings</span>
              </div>
              {investigation.findings.map((f: Finding, idx: number) => (
                <div key={f.id || idx} className="finding-item">
                  <div className="finding-header">
                    <span className="finding-title">{f.title}</span>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                  </div>
                  <p className="finding-desc">{f.description}</p>
                  <div className="finding-tags">
                    {f.attack_technique_id && <span className="tag">ATT&CK: {f.attack_technique_id}</span>}
                    {f.cwe_id && <span className="tag">CWE: {f.cwe_id}</span>}
                    <span className="tag">Evidence: {f.evidence_ids.length} Envelope(s)</span>
                  </div>
                </div>
              ))}

              {/* Uncertainties Callout */}
              <div style={{ marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px solid var(--border)' }}>
                <h4 style={{ fontSize: '0.95rem', color: '#f59e0b', marginBottom: '0.5rem' }}>
                  ⚠️ Documented Uncertainties & Missing Evidence
                </h4>
                <ul style={{ paddingLeft: '1.25rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                  {investigation.uncertainties.map((u, i) => (
                    <li key={i}>{u}</li>
                  ))}
                </ul>
              </div>

              {/* Recommended Actions */}
              <div style={{ marginTop: '1.25rem' }}>
                <h4 style={{ fontSize: '0.95rem', color: '#38bdf8', marginBottom: '0.5rem' }}>
                  🛡️ Recommended Defensive Next Steps
                </h4>
                <ul style={{ paddingLeft: '1.25rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                  {investigation.defensive_actions.map((a, i) => (
                    <li key={i}>{a}</li>
                  ))}
                </ul>
              </div>
            </section>
          )}

          {/* Tab 2: Evidence */}
          {activeTab === 'evidence' && (
            <section className="card">
              <div className="card-title">
                <span>Normalized Log Events</span>
                <span className="sample-label">Showing first 25 events normalized into UTC timestamps</span>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: '60px' }}>Line</th>
                      <th style={{ width: '180px' }}>Timestamp (UTC)</th>
                      <th style={{ width: '120px' }}>Source</th>
                      <th style={{ width: '130px' }}>Event Type</th>
                      <th>Raw Record Snippet</th>
                    </tr>
                  </thead>
                  <tbody>
                    {investigation.events_sample.map((ev: EventSample) => (
                      <tr key={ev.line_number}>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{ev.line_number}</td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{ev.timestamp.replace('T', ' ').slice(0, 19)}</td>
                        <td>{ev.source}</td>
                        <td><code>{ev.event_type}</code></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{ev.raw_line}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* Tab 3: Artifacts */}
          {activeTab === 'artifacts' && (
            <section className="card">
              <div className="card-title">
                <span>Available Response Artifacts</span>
                <span className="sample-label">Report-first human-supervised outputs</span>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
                {investigation.available_artifacts.map((art) => (
                  <button
                    key={art}
                    className={`btn btn-sm ${viewingArtifact?.name === art ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => handleLoadArtifact(art)}
                  >
                    📄 {art}
                  </button>
                ))}
              </div>

              {viewingArtifact ? (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <strong>{viewingArtifact.name}</strong>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => navigator.clipboard.writeText(viewingArtifact.content)}
                      >
                        Copy
                      </button>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => handleDownloadFile(viewingArtifact.name, viewingArtifact.content)}
                      >
                        Download
                      </button>
                    </div>
                  </div>
                  <pre className="code-block">{viewingArtifact.content}</pre>
                </div>
              ) : (
                <div style={{ color: 'var(--text-dim)', fontSize: '0.9rem' }}>
                  Select an artifact above to inspect its contents or download it locally.
                </div>
              )}
            </section>
          )}
        </>
      )}
    </div>
  );
}

export default App;
