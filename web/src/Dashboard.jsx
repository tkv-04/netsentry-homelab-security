import { useCallback, useEffect, useState } from "react";

const views = ["Overview", "Audit findings", "Change plan"];
const severityNames = { mismatch: "Blocked", review: "Review", pass: "Pass" };
const severityStyles = { mismatch: "blocked", review: "review", pass: "pass" };

function Badge({ severity, children }) {
  return <span className={`badge ${severityStyles[severity] || severity || "neutral"}`}>{children || severityNames[severity] || severity}</span>;
}

function Icon({ name }) {
  const paths = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
    shield: <><path d="M12 3 19 6v5c0 4.5-3 7.5-7 10-4-2.5-7-5.5-7-10V6l7-3Z"/><path d="m9 12 2 2 4-4"/></>,
    plan: <><path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/></>,
    refresh: <><path d="M20 7v5h-5"/><path d="M4 17v-5h5"/><path d="M5.6 9A7 7 0 0 1 18 6l2 2M4 16l2 2a7 7 0 0 0 12.4-3"/></>,
    arrow: <><path d="M7 17 17 7M7 7h10v10"/></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></>,
  };
  return <svg aria-hidden="true" viewBox="0 0 24 24" className="icon" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>;
}

async function getJson(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" }, cache: "no-store" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

function SummaryCard({ label, value, tone, note }) {
  return <article className="summary-card">
    <div className="summary-top"><span>{label}</span><span className={`summary-dot ${tone}`} /></div>
    <strong>{value ?? "—"}</strong>
    <small>{note}</small>
  </article>;
}

function FindingsTable({ findings = [] }) {
  if (!findings.length) return <div className="empty-state"><span className="empty-icon"><Icon name="shield" /></span><strong>No audit findings</strong><p>NetSentry has no observations to show for the configured policy.</p></div>;
  return <div className="table-wrap"><table><thead><tr><th>Service</th><th>Finding</th><th>Severity</th><th>Details</th></tr></thead>
    <tbody>{findings.map((item, index) => <tr key={`${item.app}-${item.code}-${index}`}>
      <td className="service-cell">{item.app}</td><td><code>{item.code}</code></td>
      <td><Badge severity={item.severity} /></td><td className="detail-cell">{item.message}</td>
    </tr>)}</tbody></table></div>;
}

function Overview({ audit, policies, onOpenAudit }) {
  const summary = audit?.summary || {};
  const apps = policies?.apps || [];
  const activeFindings = audit?.findings || [];
  return <>
    <section className="welcome-row">
      <div><div className="eyebrow">YOUR HOMELAB · SECURITY SNAPSHOT</div><h1>Exposure overview</h1>
        <p>A clear view of how your services are exposed across the network.</p></div>
      <button className="button secondary" onClick={onOpenAudit}>View audit <Icon name="arrow" /></button>
    </section>
    <section className="summary-grid" aria-label="Audit summary">
      <SummaryCard label="Policy services" value={apps.length} tone="blue" note="Defined in the local policy" />
      <SummaryCard label="Blocked" value={summary.mismatch ?? "—"} tone="red" note="Observed state conflicts with intent" />
      <SummaryCard label="Needs review" value={summary.review ?? "—"} tone="amber" note="Evidence or operator review needed" />
      <SummaryCard label="Passing checks" value={summary.pass ?? "—"} tone="green" note="Specific checks that matched" />
    </section>
    <div className="content-grid">
      <section className="panel service-panel">
        <div className="panel-heading"><div><h2>Services in policy</h2><p>Exposure intent declared for this homelab</p></div><span className="subtle-count">{apps.length} services</span></div>
        {apps.length ? <div className="service-list">{apps.map((item) => {
          const count = activeFindings.filter((finding) => finding.app === item.name && finding.severity !== "pass").length;
          return <article className="service-row" key={item.name}>
            <div className="service-mark"><Icon name="shield" /></div>
            <div className="service-meta"><strong>{item.name}</strong><span>{item.domains?.[0] || item.container_names?.[0] || "No domain configured"}</span></div>
            <span className="exposure-pill">{item.exposure}</span>
            <span className={`finding-count ${count ? "has-findings" : ""}`}>{count || "—"}</span>
          </article>;
        })}</div> : <div className="empty-state compact"><strong>No policies loaded</strong><p>Add services to your local policy file to see exposure intent here.</p></div>}
      </section>
      <section className="panel attention-panel">
        <div className="panel-heading"><div><h2>Needs attention</h2><p>Top findings from the latest audit</p></div><span className="attention-count">{activeFindings.filter((finding) => finding.severity !== "pass").length}</span></div>
        <div className="attention-list">{activeFindings.filter((finding) => finding.severity !== "pass").slice(0, 5).map((finding, index) => <div className="attention-row" key={`${finding.code}-${index}`}>
          <span className={`attention-mark ${severityStyles[finding.severity]}`}><Icon name={finding.severity === "mismatch" ? "lock" : "shield"} /></span>
          <div><strong>{finding.app}</strong><span>{finding.message}</span></div><Badge severity={finding.severity} />
        </div>)}
          {!activeFindings.some((finding) => finding.severity !== "pass") && <div className="quiet-state"><span>✓</span><strong>Nothing needs attention</strong><p>Refresh the audit to check the latest state.</p></div>}
        </div>
      </section>
    </div>
    <section className="panel policy-note"><span className="note-icon"><Icon name="lock" /></span><div><strong>Read-only dashboard</strong><p>This dashboard inspects your current setup and shows proposed changes. It never applies Caddy, Docker, or firewall changes.</p></div></section>
  </>;
}

function AuditView({ audit }) {
  return <>
    <section className="welcome-row"><div><div className="eyebrow">POLICY COMPARISON</div><h1>Audit findings</h1><p>Observed configuration compared with the exposure intent in your policy file.</p></div></section>
    <section className="summary-grid compact-grid">
      <SummaryCard label="Blocked" value={audit?.summary?.mismatch ?? "—"} tone="red" note="Requires a configuration decision" />
      <SummaryCard label="Needs review" value={audit?.summary?.review ?? "—"} tone="amber" note="Evidence is incomplete or ambiguous" />
      <SummaryCard label="Passing checks" value={audit?.summary?.pass ?? "—"} tone="green" note="A specific audit condition matched" />
    </section>
    <section className="panel"><div className="panel-heading"><div><h2>All findings</h2><p>Each row explains one observed condition</p></div></div><FindingsTable findings={audit?.findings} /></section>
  </>;
}

function PlanView({ plan }) {
  return <>
    <section className="welcome-row"><div><div className="eyebrow">DRY-RUN ONLY</div><h1>Change plan</h1><p>Review proposed Caddy additions and unresolved blockers. Nothing is applied here.</p></div></section>
    <section className="plan-summary">
      <div className="plan-stat"><span>Routes proposed</span><strong>{plan?.summary?.proposed ?? "—"}</strong></div>
      <div className="plan-stat"><span>Needs review</span><strong>{plan?.summary?.review ?? "—"}</strong></div>
      <div className="plan-stat"><span>Blocked</span><strong>{plan?.summary?.blocked ?? "—"}</strong></div>
      <div className="plan-state"><Badge severity={plan?.summary?.blocked ? "mismatch" : "pass"}>{plan?.summary?.blocked ? "Review required" : "Ready to review"}</Badge><span>Planner does not apply changes</span></div>
    </section>
    <section className="panel"><div className="panel-heading"><div><h2>Proposals and conflicts</h2><p>Only supported route additions are shown as diffs</p></div></div>
      <div className="plan-list">{(plan?.items || []).map((item, index) => <article className="plan-item" key={`${item.code}-${index}`}><div className="plan-item-head"><div><strong>{item.app}</strong><code>{item.code}</code></div><Badge severity={item.status === "blocked" ? "mismatch" : item.status === "proposed" ? "pass" : "review"}>{item.status}</Badge></div><p>{item.message}</p></article>)}</div>
    </section>
    <section className="panel diff-panel"><div className="panel-heading"><div><h2>Proposed Caddy diff</h2><p>Review this suggestion separately with your Caddy configuration</p></div></div>
      {plan?.diff ? <pre className="diff"><code>{plan.diff}</code></pre> : <div className="empty-state compact"><strong>No route changes proposed</strong><p>The planner has no safe Caddy additions for the current observations.</p></div>}
      <div className="read-only-callout"><Icon name="lock" /><span>{plan?.note || "Plan is read-only; no configuration was changed."}</span></div>
    </section>
  </>;
}

export default function Dashboard() {
  const [view, setView] = useState("Overview");
  const [audit, setAudit] = useState(null);
  const [plan, setPlan] = useState(null);
  const [policies, setPolicies] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState(null);

  const refresh = useCallback(async () => {
    setRefreshing(true); setError("");
    try {
      const [overview, nextPlan, policyData] = await Promise.all([
        getJson("/api/audit"), getJson("/api/plan"), getJson("/api/policies"),
      ]);
      setAudit(overview); setPlan(nextPlan); setPolicies(policyData); setUpdatedAt(new Date());
    } catch (requestError) { setError(requestError.message || "Could not load dashboard data"); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  const mismatch = audit?.summary?.mismatch || 0;
  const review = audit?.summary?.review || 0;
  const isHealthy = audit && mismatch === 0 && review === 0;

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-symbol"><Icon name="shield" /></div><div><strong>NetSentry</strong><span>Homelab security</span></div></div>
      <div className="nav-caption">WORKSPACE</div>
      <nav aria-label="Dashboard sections">{views.map((item) => <button className={`nav-item ${view === item ? "active" : ""}`} key={item} onClick={() => setView(item)}>
        <Icon name={item === "Overview" ? "grid" : item === "Audit findings" ? "shield" : "plan"}/><span>{item}</span>{item === "Audit findings" && mismatch > 0 && <em>{mismatch}</em>}
      </button>)}</nav>
      <div className="sidebar-bottom"><div className="read-only-lock"><Icon name="lock"/><div><strong>Read-only mode</strong><span>Changes need your review</span></div></div><div className="sidebar-version">NETSENTRY · PHASE 5</div></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="breadcrumb"><span>Workspace</span><b>/</b><strong>{view}</strong></div><div className="topbar-actions"><div className="live-state"><i className={isHealthy ? "healthy" : audit ? "attention" : ""} />{loading ? "Connecting" : isHealthy ? "All checks clear" : "Review findings"}</div><button className="icon-button" onClick={refresh} disabled={refreshing} aria-label="Refresh data" title="Refresh data"><span className={refreshing ? "spin" : ""}><Icon name="refresh" /></span></button></div></header>
      <div className="main-content">
        {error && <div className="error-banner" role="alert"><strong>Couldn’t load dashboard data</strong><span>{error}</span><button onClick={refresh}>Retry</button></div>}
        {loading && !audit ? <div className="loading-panel"><span className="spinner"/><strong>Loading your security overview…</strong><span>Reading policy and local inspection data</span></div> : <>
          {view === "Overview" && <Overview audit={audit} policies={policies} onOpenAudit={() => setView("Audit findings")} />}
          {view === "Audit findings" && <AuditView audit={audit} />}
          {view === "Change plan" && <PlanView plan={plan} />}
        </>}
      </div>
      <footer className="footer"><span>NetSentry inspects; you decide.</span><span>{updatedAt ? `Updated ${updatedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "Waiting for data"}</span></footer>
    </main>
  </div>;
}
