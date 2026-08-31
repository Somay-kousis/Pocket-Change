// The gateway, as the console sees it.
//
// Every number on screen comes from here. Nothing is generated, estimated or
// animated into existence — the previous console produced mandate ids with
// Math.random() and paid imaginary sellers on a timer, which looked convincing
// and told you nothing about whether the system worked.

// Same-origin when the console is served by the gateway itself, which is how it
// is deployed; localhost only when running `npm run dev` against a local API.
// An empty base means every fetch is a relative path, so there is no CORS
// preflight and nothing to configure.
// Optional-chained: Vite substitutes import.meta.env at build time, but the
// bare expression throws anywhere it has not been substituted.
const DEFAULT = import.meta.env?.DEV ? 'http://localhost:8080' : ''

export const url = () =>
  (localStorage.getItem('pc.gateway') ?? DEFAULT).replace(/\/$/, '')

// Public by design. This gates writes so a crawler cannot drain a shared free
// tier mid-judging; it is a brake, not authentication, and anyone who opens
// devtools has it. Reads never need it.
const DEMO_TOKEN =
  localStorage.getItem('pc.token') || import.meta.env?.VITE_DEMO_TOKEN || ''

const writeHeaders = () => ({
  'Content-Type': 'application/json',
  ...(DEMO_TOKEN ? { 'X-Demo-Token': DEMO_TOKEN } : {}),
})

async function json(path, init, timeout = 5000) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)
  try {
    const response = await fetch(url() + path, { ...init, signal: controller.signal })
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      const error = new Error(`${path} → ${response.status}`)
      error.status = response.status
      error.detail = body.detail ?? body
      throw error
    }
    return response.json()
  } finally {
    clearTimeout(timer)
  }
}

const post = (path, body) => json(path, {
  method: 'POST',
  headers: writeHeaders(),
  body: JSON.stringify(body),
})

export const health    = () => json('/status')
export const audit     = () => json('/audit')
export const approvals = () => json('/approvals')
export const mandate   = (id) => json(`/mandates/${id}`)
export const events    = (limit = 800) => json(`/events?limit=${limit}`)

// The floor is where splitting stops, and it has to be set relative to the
// budget rather than as a fixed rupee figure. Left at a flat ₹5,000 under a
// ₹2,00,000 ceiling, every node in the tree stays "big enough to split", so
// every node is granted `delegate` — including the ones that turn out to be
// leaves. The floor is what makes a leaf a leaf.
export const floorFor = (rupees) => Math.max(1000, Math.round(rupees / 8))

export const startRun = (task, budgetRupees, options = {}) => post('/runs', {
  task,
  budget_paise: Math.round(budgetRupees * 100),
  fan_out: options.fanOut ?? 3,
  max_depth: options.maxDepth ?? 8,
  floor_paise: Math.round((options.floorRupees ?? floorFor(budgetRupees)) * 100),
  decomposer: options.decomposer ?? 'auto',
  monitor: options.monitor ?? true,
})

// The front door. One sentence in; what the gateway understood, and the
// questions it still needs answered, out. Costs at most one model call and
// mints nothing — a proposal only becomes a mandate at startProposal.
//
// 20s rather than the default 5: this waits on a model, and a front door that
// times out before the model answers sends people straight back to the form it
// replaced.
export const readRequest = (text, answers = {}, options = {}) =>
  json('/intake', {
    method: 'POST',
    headers: writeHeaders(),
    body: JSON.stringify({
      text,
      answers,
      fan_out: options.fanOut ?? 3,
      max_depth: options.maxDepth ?? 8,
      monitor: options.monitor ?? true,
      critic: options.critic ?? true,
    }),
  }, 20000)

// Posts the proposal back verbatim. Deliberately not reassembled here: the
// gateway validated that exact object, and rebuilding it in the browser is how
// a field quietly stops matching what was confirmed on screen.
export const startProposal = (proposal) => post('/runs', proposal)

export const verifyChain = () => json('/audit/verify')
export const counterparties = () => json('/counterparties')
export const agents = () => json('/agents')
// include_pending, because a policy waiting on a person is the state most
// worth showing - the tick loop still reads the narrow default.
export const standing = () => json('/standing?include_pending=true')
export const replay = (auditSeq) => post(`/replay/${auditSeq}`)

// The operator credential. Unlike the demo token it is never built into the
// page: the person deciding pastes it once and this browser keeps it. Without
// it the gateway refuses every decision, because the agent whose payment is
// held must not be the one releasing it.
const operatorToken = () => {
  let token = localStorage.getItem('pc.operator') || ''
  if (!token && typeof window !== 'undefined' && window.prompt) {
    token = (window.prompt('Operator token (POCKETCHANGE_OPERATOR_TOKEN):') || '').trim()
    if (token) localStorage.setItem('pc.operator', token)
  }
  return token
}

export const decide = async (id, approve) => {
  const token = operatorToken()
  try {
    return await json(`/approvals/${id}`, {
      method: 'POST',
      headers: { ...writeHeaders(), ...(token ? { 'X-Operator-Token': token } : {}) },
      body: JSON.stringify({ decision: approve ? 'approve' : 'deny', by: 'console', note: '' }),
    })
  } catch (error) {
    // A stale or mistyped token is forgotten so the next click asks again.
    if (error.status === 401) localStorage.removeItem('pc.operator')
    throw error
  }
}

// --- live ------------------------------------------------------------------
//
// EventSource reconnects by itself, and the gateway replays its buffer on each
// connection, so the caller must key events rather than append them.

const KINDS = [
  'spawned', 'granted', 'decomposed', 'searching', 'paying',
  'allowed', 'denied', 'escalated', 'settled', 'bound_hit',
]

export function stream({ onEvent, onOpen, onError }) {
  let source
  try {
    source = new EventSource(`${url()}/stream?replay=true`)
  } catch {
    onError?.()
    return () => {}
  }
  for (const kind of KINDS) {
    source.addEventListener(kind, (message) => {
      try { onEvent(JSON.parse(message.data)) } catch { /* a bad frame is not fatal */ }
    })
  }
  source.addEventListener('open', () => onOpen?.())
  source.addEventListener('error', () => onError?.())
  return () => source.close()
}
