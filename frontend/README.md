# SentinelAI Frontend (React + TypeScript + Vite)

The SentinelAI frontend provides a clean, operator-focused cybersecurity investigation interface designed for local development.

## Features

- **Security Log Upload**: Drag-and-drop or file selector supporting `.log`, `.txt`, `.json`, `.jsonl`, and `.csv`.
- **Preloaded Test Fixtures**: 1-click loading for Brute-Force SSH, Apache Log4Shell exploitation, and Suspicious JSON audit events.
- **Incident Overview**: Displays severity badge, confidence rating, affected entities, and summary.
- **Evidence-Backed Findings**: Each security finding links directly to normalized log evidence and original line numbers.
- **Raw Evidence Viewer**: Paginated and searchable view of parsed log lines with indicator chips.
- **Response Artifact Downloads**: View and download markdown reports (`response_report.md`, `suggested_changes.md`, `agent_prompt.md`, `response_plan.md`) and machine-readable data (`findings.json`).
- **Human Approval Gate**: Review proposed remediation actions with target parameters, risk level, and rationale. Operators can explicitly approve or reject actions.
- **Server Kill Switch**: View and toggle the server-side tool execution kill switch.

---

## Prerequisites

- Node.js 20+ (Node v24 tested)
- npm 10+

---

## Setup & Configuration

1. Install dependencies:
   ```bash
   cd frontend
   npm install
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   ```
   Default content of `.env`:
   ```bash
   VITE_API_BASE_URL=http://localhost:8000
   ```

---

## Running Locally

Start the Vite development server:
```bash
npm run dev
```
By default, the UI will be available at: `http://localhost:5173`

---

## Verification & Build

- **Type Check & Build**:
  ```bash
  npm run build
  ```
- **Linting**:
  ```bash
  npm run lint
  ```
