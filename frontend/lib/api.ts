/**
 * AI Shield — API Client
 * Typed fetch wrapper for the FastAPI backend.
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8002'

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  token?: string,
): Promise<T> {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  }
  const res = await fetch(`${API_URL}${path}`, { ...options, headers })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail?.message || err.detail || res.statusText)
  }
  return res.json()
}

// ── Types ─────────────────────────────────────────────────────────────────────
export interface Detection {
  detector: string
  detected: boolean
  severity: string
  confidence: number
  mitre_atlas: string[]
  details: Record<string, unknown>
}

export interface DetectionResponse {
  action: string
  severity: string
  blocked: boolean
  detections: Detection[]
  tenant_id: string
}

export interface HealthResponse {
  status: string
  version: string
  dependencies: {
    threatfade: { status: string; latency_ms?: number }
    postgres:   { status: string; latency_ms?: number }
    redis:      { status: string; latency_ms?: number }
  }
}

export interface SummaryResponse {
  days: number
  total: number
  blocked: number
  alerted: number
}

export interface BlockedItem {
  type: 'model' | 'agent'
  id: string
  reason: string
  expires_in_seconds: number
}

// ── API methods ───────────────────────────────────────────────────────────────
export const api = {
  health: (token?: string) =>
    apiFetch<HealthResponse>('/health', {}, token),

  detectLLM: (
    prompt: string,
    completion?: string,
    model?: string,
    token?: string,
  ) =>
    apiFetch<DetectionResponse>('/detect/llm', {
      method: 'POST',
      body: JSON.stringify({ prompt, completion, model }),
    }, token),

  detectPrompt: (prompt: string, token?: string) =>
    apiFetch<{ blocked: boolean; severity: string }>('/detect/prompt', {
      method: 'POST',
      body: JSON.stringify({ prompt }),
    }, token),

  summary: (days = 7, token?: string) =>
    apiFetch<SummaryResponse>(`/reports/summary?days=${days}`, {}, token),

  listBlocked: (token?: string) =>
    apiFetch<{ blocked_count: number; blocked: BlockedItem[] }>(
      '/enforce/blocked', {}, token
    ),

  blockModel: (target_id: string, reason: string, token?: string) =>
    apiFetch('/enforce/block', {
      method: 'POST',
      body: JSON.stringify({ target_type: 'model', target_id, reason }),
    }, token),

  unblockModel: (target_id: string, token?: string) =>
    apiFetch('/enforce/unblock', {
      method: 'POST',
      body: JSON.stringify({ target_type: 'model', target_id, reason: '' }),
    }, token),
}
