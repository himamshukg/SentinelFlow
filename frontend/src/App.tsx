import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

type Decision = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
type Health = { status: string; version: string };
type AgentIdentity = { agent_id: string };
type Scenario = {
  scenario_id: string;
  title: string;
  explanation: string;
  action: string;
  agent_id: string;
  arguments: unknown;
  expected_decision: Decision;
  expected_executed: boolean;
  expected_rule_id: string;
};
type AuditEvent = {
  request_id: string;
  event: string;
  action: string | null;
  arguments: Record<string, unknown> | null;
  agent_id: string | null;
  decision: Decision;
  rule_id: string;
  reason: string;
  executed: boolean;
  execution_success: boolean;
  pending: boolean;
  error: string | null;
  timestamp?: string;
  created_at?: string;
};
type EvaluateResult = {
  request_id: string;
  decision: Decision;
  rule_id: string;
  reason: string;
  executed: boolean;
  execution_success: boolean;
  pending: boolean;
  error: string | null;
  output: Record<string, unknown> | null;
};

async function apiGet<T>(path: string, agentToken = ""): Promise<T> {
  const headers = agentToken ? { Authorization: `Bearer ${agentToken}` } : undefined;
  const response = await fetch(`${API_BASE_URL}${path}`, { headers });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(payload?.error?.message || `Request failed (${response.status}).`);
  }
  return payload as T;
}

async function apiPost<T>(path: string, body: unknown, agentToken: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${agentToken}` },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const message = payload?.error?.message || "The API rejected this request.";
    const fields = payload?.error?.details?.map((item: { field?: string; message?: string }) =>
      [item.field, item.message].filter(Boolean).join(": "),
    );
    throw new Error([message, ...(fields || [])].join(" "));
  }
  return payload as T;
}

function DecisionBadge({ decision }: { decision: string }) {
  const type = decision === "ALLOW" ? "allow" : decision === "BLOCK" ? "block" : "approval";
  return <span className={`decision-badge ${type}`}><i />{decision.replaceAll("_", " ")}</span>;
}

function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState("");
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenarioError, setScenarioError] = useState("");
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [eventsError, setEventsError] = useState("");
  const [agentToken, setAgentToken] = useState("");
  const [authenticatedAgentId, setAuthenticatedAgentId] = useState("");
  const [credentialInput, setCredentialInput] = useState("");
  const [credentialError, setCredentialError] = useState("");
  const [connectingCredential, setConnectingCredential] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshingEvents, setRefreshingEvents] = useState(false);
  const [decisionFilter, setDecisionFilter] = useState("ALL");
  const [selectedScenario, setSelectedScenario] = useState("");
  const [action, setAction] = useState("");
  const [agentId, setAgentId] = useState("");
  const [argumentsText, setArgumentsText] = useState("{}\n");
  const [submitting, setSubmitting] = useState(false);
  const [evaluateError, setEvaluateError] = useState("");
  const [result, setResult] = useState<EvaluateResult | null>(null);
  const scenarioInitialized = useRef(false);

  const refreshAll = useCallback(async () => {
    setLoading(true);
    const [healthResult, scenarioResult, eventResult] = await Promise.allSettled([
      apiGet<Health>("/api/health"),
      apiGet<{ scenarios: Scenario[] }>("/api/scenarios"),
      apiGet<{ events: AuditEvent[]; count: number }>("/api/events?limit=200", agentToken),
    ]);
    if (healthResult.status === "fulfilled") {
      setHealth(healthResult.value);
      setHealthError("");
    } else {
      setHealth(null);
      setHealthError(healthResult.reason instanceof Error ? healthResult.reason.message : "Could not reach API.");
    }
    if (scenarioResult.status === "fulfilled") {
      setScenarios(scenarioResult.value.scenarios);
      setScenarioError("");
      if (!scenarioInitialized.current && scenarioResult.value.scenarios.length > 0) {
        const first = scenarioResult.value.scenarios[0];
        scenarioInitialized.current = true;
        setSelectedScenario(first.scenario_id);
        setAction(first.action);
        setAgentId(first.agent_id);
        setArgumentsText(JSON.stringify(first.arguments, null, 2));
      }
    } else {
      setScenarioError(scenarioResult.reason instanceof Error ? scenarioResult.reason.message : "Could not load scenarios.");
    }
    if (eventResult.status === "fulfilled") {
      setEvents(eventResult.value.events);
      setEventsError("");
    } else {
      setEvents(null);
      setEventsError(eventResult.reason instanceof Error ? eventResult.reason.message : "Could not load events.");
    }
    setLoading(false);
  }, [agentToken]);

  const refreshEvents = useCallback(async () => {
    setRefreshingEvents(true);
    try {
      const payload = await apiGet<{ events: AuditEvent[]; count: number }>("/api/events?limit=200", agentToken);
      setEvents(payload.events);
      setEventsError("");
    } catch (error) {
      setEventsError(error instanceof Error ? error.message : "Could not load events.");
    } finally {
      setRefreshingEvents(false);
    }
  }, [agentToken]);

  useEffect(() => { void refreshAll(); }, [refreshAll]);

  const metrics = useMemo(() => {
    if (events === null) return null;
    return {
      total: events.length,
      allowed: events.filter((event) => event.decision === "ALLOW").length,
      blocked: events.filter((event) => event.decision === "BLOCK").length,
      approval: events.filter((event) => event.decision === "REQUIRE_APPROVAL").length,
    };
  }, [events]);

  const visibleEvents = useMemo(() => {
    if (!events) return [];
    return decisionFilter === "ALL" ? events : events.filter((event) => event.decision === decisionFilter);
  }, [events, decisionFilter]);

  const credentialMismatch = Boolean(
    authenticatedAgentId && agentId && authenticatedAgentId !== agentId.trim(),
  );

  const handleScenarioChange = (scenarioId: string) => {
    setSelectedScenario(scenarioId);
    const scenario = scenarios.find((item) => item.scenario_id === scenarioId);
    if (!scenario) return;
    setAction(scenario.action);
    setAgentId(scenario.agent_id);
    setArgumentsText(JSON.stringify(scenario.arguments, null, 2));
    setEvaluateError("");
    setResult(null);
    if (authenticatedAgentId !== scenario.agent_id) {
      setEvaluateError(
        authenticatedAgentId
          ? `You are connected as ${authenticatedAgentId}. Connect as ${scenario.agent_id} to use this scenario.`
          : `Connect with the server credential for ${scenario.agent_id} to use this scenario.`,
      );
    }
  };

  const connectAgentCredential = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const token = credentialInput.trim();
    if (!token) {
      setCredentialError("Paste an agent credential first.");
      return;
    }
    setConnectingCredential(true);
    setCredentialError("");
    try {
      const identity = await apiGet<AgentIdentity>("/api/identity", token);
      setAgentToken(token);
      setAuthenticatedAgentId(identity.agent_id);
      setCredentialInput("");
      setEvaluateError("");
    } catch (error) {
      setCredentialError(error instanceof Error ? error.message : "Could not connect this credential.");
      setConnectingCredential(false);
      return;
    }
    try {
      const payload = await apiGet<{ events: AuditEvent[]; count: number }>("/api/events?limit=200", token);
      setEvents(payload.events);
      setEventsError("");
    } catch (error) {
      setEventsError(error instanceof Error ? error.message : "Could not load audit events.");
    } finally {
      setConnectingCredential(false);
    }
  };

  const submitProposal = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setEvaluateError("");
    setResult(null);
    if (!agentToken || !authenticatedAgentId) {
      setEvaluateError("Connect an agent credential before evaluating a proposal.");
      return;
    }
    if (credentialMismatch) {
      setEvaluateError(
        `You are connected as ${authenticatedAgentId}, but this proposal uses ${agentId}. Connect the matching agent credential first.`,
      );
      return;
    }
    let args: unknown;
    try {
      args = JSON.parse(argumentsText);
    } catch {
      setEvaluateError("Arguments must be valid JSON. Check commas, quotes, and braces.");
      return;
    }
    setSubmitting(true);
    try {
      const evaluated = await apiPost<EvaluateResult>("/api/evaluate", {
        action: action.trim(),
        arguments: args,
        agent_id: agentId.trim(),
      }, agentToken);
      setResult(evaluated);
      void refreshEvents();
    } catch (error) {
      setEvaluateError(error instanceof Error ? error.message : "Evaluation failed. Check that the API is available.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview" aria-label="SentinelFlow home">
          <span className="brand-mark"><span /></span>
          <span className="brand-copy"><strong>Sentinel<span>Flow</span></strong><small>AGENT SECURITY GATEWAY</small></span>
        </a>
        <div className="sidebar-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Main navigation">
          <a className="nav-item active" href="#overview"><span className="nav-icon">▦</span>Overview</a>
          <a className="nav-item" href="#simulator"><span className="nav-icon">⌘</span>Action simulator</a>
          <a className="nav-item" href="#events"><span className="nav-icon">≋</span>Security events</a>
          <a className="nav-item" href="#scenarios"><span className="nav-icon">◈</span>Scenarios</a>
        </nav>
        <div className="sidebar-bottom">
          <div className="system-card">
            <div className="system-card-title"><span className={`status-dot ${health ? "online" : "offline"}`} />API STATUS</div>
            <strong>{health ? "Gateway online" : "Gateway unavailable"}</strong>
            <span>{health ? `Version ${health.version}` : "Check backend connection"}</span>
          </div>
          <div className="sidebar-foot"><span className="shield-mini">◆</span> Simulation environment <span className="live-dot" /></div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumb">SentinelFlow <span>/</span> <strong>Overview</strong></div>
          <div className="topbar-right">
            <span className="environment-chip"><i /> LOCAL ENVIRONMENT</span>
            <button className="icon-button" onClick={() => void refreshAll()} aria-label="Refresh dashboard" title="Refresh dashboard">↻</button>
            <div className="avatar">SF</div>
          </div>
        </header>

        <div className="page-wrap">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> SECURITY OPERATIONS</div>
              <h1>Gateway overview</h1>
              <p>Monitor agent requests and evaluate tool actions against your security policies.</p>
            </div>
            <div className={`connection-pill ${health ? "connected" : "disconnected"}`}>
              <span className={`status-dot ${health ? "online" : "offline"}`} />
              {health ? "API connected" : "API disconnected"}
            </div>
          </section>

          {healthError && <div className="inline-error" role="alert"><strong>Backend connection failed.</strong> {healthError} Check the API URL and start the backend.</div>}

          <form className="agent-credential" onSubmit={connectAgentCredential}>
            <div><label htmlFor="agent-credential">Agent credential</label><small>{authenticatedAgentId ? `Connected as ${authenticatedAgentId}. Token stays in page memory.` : "Connect the server-configured token for your selected agent."}</small></div>
            <input id="agent-credential" type="password" autoComplete="off" value={credentialInput} onChange={(event) => setCredentialInput(event.target.value)} placeholder="Paste agent token" />
            <button className="secondary-button" type="submit" disabled={connectingCredential}>{connectingCredential ? "Checking…" : "Connect"}</button>
            {agentToken && <button className="secondary-button" type="button" onClick={() => { setAgentToken(""); setAuthenticatedAgentId(""); setEvents(null); setEventsError("Connect an agent credential to load audit events."); setCredentialError(""); }}>Disconnect</button>}
          </form>
          {credentialError && <div className="inline-error compact" role="alert">Credential not connected: {credentialError}</div>}
          {credentialMismatch && <div className="identity-warning" role="status">This proposal is for <strong>{agentId}</strong>, but the connected credential belongs to <strong>{authenticatedAgentId}</strong>. Connect the matching credential to continue.</div>}

          <section className="metrics-grid" aria-label="Security event summary">
            <MetricCard label="Events loaded" value={metrics?.total} tone="blue" icon="⌁" foot="Latest API event feed" />
            <MetricCard label="Allowed actions" value={metrics?.allowed} tone="green" icon="✓" foot="Policy permitted" />
            <MetricCard label="Blocked actions" value={metrics?.blocked} tone="red" icon="⛨" foot="Policy denied" />
            <MetricCard label="Needs approval" value={metrics?.approval} tone="amber" icon="◷" foot="Held for human review" />
          </section>
          <div className="feed-note"><span className="info-icon">i</span> Counts reflect the latest events returned by the API (up to 200). The backend does not currently expose a lifetime total.</div>

          <section className="work-grid">
            <section className="panel simulator-panel" id="simulator">
              <div className="panel-heading">
                <div className="panel-title-wrap"><span className="panel-icon blue-icon">⌘</span><div><h2>Action simulator</h2><p>Submit a proposal for backend policy evaluation</p></div></div>
                <span className="backend-only"><span /> BACKEND AUTHORIZED</span>
              </div>
              <form onSubmit={submitProposal}>
                <div className="field-group" id="scenarios">
                  <label htmlFor="scenario-select">Start from a scenario <span>OPTIONAL</span></label>
                  {scenarioError ? <div className="field-error" role="alert">Scenarios unavailable: {scenarioError}</div> : (
                    <select id="scenario-select" value={selectedScenario} onChange={(event) => handleScenarioChange(event.target.value)}>
                      <option value="">Custom proposal</option>
                      {scenarios.length === 0 && <option value="" disabled>{loading ? "Loading scenarios…" : "No scenarios available"}</option>}
                      {scenarios.map((scenario) => <option key={scenario.scenario_id} value={scenario.scenario_id}>{scenario.title}</option>)}
                    </select>
                  )}
                  {scenarios.find((scenario) => scenario.scenario_id === selectedScenario) && <p className="scenario-hint">{scenarios.find((scenario) => scenario.scenario_id === selectedScenario)?.explanation}</p>}
                </div>
                <div className="field-row">
                  <div className="field-group"><label htmlFor="action-input">Tool action</label><input id="action-input" required maxLength={64} value={action} onChange={(event) => { setAction(event.target.value); setSelectedScenario(""); }} placeholder="e.g. read_file" /></div>
                  <div className="field-group"><label htmlFor="agent-input">Agent identity</label><input id="agent-input" required maxLength={64} value={agentId} onChange={(event) => { setAgentId(event.target.value); setSelectedScenario(""); }} placeholder="e.g. docs_agent" /></div>
                </div>
                <div className="field-group">
                  <div className="label-row"><label htmlFor="arguments-input">Arguments</label><span className="format-label">JSON VALUE</span></div>
                  <div className="code-input-wrap"><span className="line-number">1</span><textarea id="arguments-input" rows={6} spellCheck={false} value={argumentsText} onChange={(event) => { setArgumentsText(event.target.value); setSelectedScenario(""); }} aria-describedby="arguments-help" /></div>
                  <div id="arguments-help" className="field-help">Malformed JSON shapes can be tested too; the backend policy engine decides and blocks invalid arguments. The frontend never runs tools or decides authorization.</div>
                </div>
                {evaluateError && <div className="inline-error compact" role="alert">{evaluateError}</div>}
                <div className="form-footer"><span className="mock-note"><span className="mock-icon">◇</span> Mock tools only · No external actions</span><button className="primary-button" type="submit" disabled={submitting || connectingCredential || !health || !agentToken || credentialMismatch}>{submitting ? <><span className="spinner" /> Evaluating…</> : <>Evaluate proposal <span>→</span></>}</button></div>
              </form>
            </section>

            <section className={`panel result-panel ${result ? `result-${result.decision.toLowerCase()}` : ""}`} aria-live="polite">
              <div className="panel-heading result-heading"><div className="panel-title-wrap"><span className="panel-icon violet-icon">◈</span><div><h2>Policy decision</h2><p>Returned by the SentinelFlow backend</p></div></div></div>
              {result ? (
                <div className="result-content">
                  <div className="result-topline"><span className="result-label">DECISION</span><DecisionBadge decision={result.decision} /></div>
                  <p className="result-reason">{result.reason}</p>
                  <div className="rule-row"><span>Policy rule</span><code>{result.rule_id}</code></div>
                  <div className="result-facts">
                    <div><span>Mock execution</span><strong className={result.executed ? "text-green" : "text-muted"}>{result.executed ? "Executed" : result.pending ? "Waiting for approval" : "Not executed"}</strong></div>
                    <div><span>Execution status</span><strong>{result.execution_success ? "Success" : result.error ? "Failed" : "—"}</strong></div>
                    <div><span>Request ID</span><strong className="mono">{result.request_id}</strong></div>
                  </div>
                  {result.error && <div className="result-error">{result.error}</div>}
                  {result.output && <details className="output-details"><summary>View redacted mock output</summary><pre>{JSON.stringify(result.output, null, 2)}</pre></details>}
                  <div className="decision-footnote">Decision and execution outcome are supplied by the backend.</div>
                </div>
              ) : (
                <div className="empty-result"><div className="empty-shield">◇</div><strong>Ready to evaluate</strong><p>Choose a scenario or enter a proposal. The backend will return the policy decision here.</p><div className="decision-legend"><span><i className="legend-green" /> ALLOW</span><span><i className="legend-red" /> BLOCK</span><span><i className="legend-amber" /> REQUIRE APPROVAL</span></div></div>
              )}
            </section>
          </section>

          <section className="panel events-panel" id="events">
            <div className="events-heading">
              <div className="panel-title-wrap"><span className="panel-icon teal-icon">≋</span><div><h2>Security event log</h2><p>Recent requests recorded by the backend audit log</p></div></div>
              <div className="event-controls"><label className="filter-label" htmlFor="decision-filter">Decision</label><select id="decision-filter" value={decisionFilter} onChange={(event) => setDecisionFilter(event.target.value)}><option value="ALL">All decisions</option><option value="ALLOW">Allowed</option><option value="BLOCK">Blocked</option><option value="REQUIRE_APPROVAL">Needs approval</option></select><button className="secondary-button" onClick={() => void refreshEvents()} disabled={refreshingEvents}>{refreshingEvents ? <span className="spinner dark-spinner" /> : "↻"} Refresh</button></div>
            </div>
            {eventsError && <div className="inline-error compact" role="alert">Could not load audit events: {eventsError}</div>}
            {events === null && !eventsError ? <div className="table-state"><span className="spinner dark-spinner" /> Loading audit events…</div> : events !== null && visibleEvents.length === 0 ? <div className="table-state empty-state"><span className="empty-table-icon">≋</span><strong>{events.length === 0 ? "No security events yet" : "No events match this filter"}</strong><span>{events.length === 0 ? "Evaluate a proposal to create the first audit record." : "Choose another decision filter to view more events."}</span></div> : events !== null && (
              <div className="table-scroll"><table><thead><tr><th>TIMESTAMP</th><th>REQUESTED ACTION</th><th>DECISION</th><th>REASON</th><th>EXECUTION</th></tr></thead><tbody>
                {visibleEvents.map((item) => <tr key={`${item.request_id}-${item.event}`}><td className="time-cell">{formatTimestamp(item.timestamp || item.created_at)}</td><td><div className="action-cell"><strong>{item.action || "Unknown action"}</strong><span>{item.agent_id || "Unknown agent"} · {item.request_id}</span></div></td><td><DecisionBadge decision={item.decision} /></td><td className="reason-cell" title={item.reason}>{item.reason}</td><td><ExecutionStatus event={item} /></td></tr>)}
              </tbody></table></div>
            )}
            <div className="table-footer"><span>Showing {visibleEvents.length} of {events?.length ?? "—"} loaded events</span><span className="audit-state"><i /> Audit feed connected to API</span></div>
          </section>

          <footer className="page-footer"><span>SentinelFlow <b>·</b> AI Agent Security Gateway</span><span>Policy first. Simulated execution only.</span></footer>
        </div>
      </main>
    </div>
  );
}

function MetricCard({ label, value, tone, icon, foot }: { label: string; value: number | undefined; tone: string; icon: string; foot: string }) {
  return <article className="metric-card"><div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}>{icon}</span></div><strong className="metric-value">{value === undefined ? "—" : value.toLocaleString()}</strong><div className="metric-foot"><span className={`metric-mark ${tone}`} />{foot}</div></article>;
}

function ExecutionStatus({ event }: { event: AuditEvent }) {
  if (event.pending) return <span className="execution-status pending"><i /> Pending approval</span>;
  if (event.event === "execution_started") return <span className="execution-status idle"><i /> Outcome unknown</span>;
  if (event.execution_success) return <span className="execution-status success"><i /> Executed</span>;
  if (event.error) return <span className="execution-status failed"><i /> Failed</span>;
  return <span className="execution-status idle"><i /> Not executed</span>;
}

function formatTimestamp(value?: string) {
  if (!value) return <span className="timestamp-missing" title="The current audit API does not provide timestamps">— <small>unavailable</small></span>;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export default App;
