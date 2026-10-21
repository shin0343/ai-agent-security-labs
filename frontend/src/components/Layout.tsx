import { NavLink, Outlet, useLocation } from "react-router-dom";
import { relativeTime } from "../lib/format";
import { useSession } from "../state/SessionContext";
import { useWorkspace } from "../state/WorkspaceContext";
import { Button, StatusBadge } from "./ui";

const NAV_ITEMS = [
  { to: "/", label: "Overview", index: "01", end: true },
  { to: "/investigations", label: "Investigations", index: "02" },
  { to: "/traces", label: "Agent traces", index: "03" },
  { to: "/policies", label: "Policy & approvals", index: "04" },
  { to: "/evaluation", label: "Evaluation", index: "05" },
  { to: "/audit", label: "Audit & cases", index: "06" },
];

const PAGE_TITLES: Record<string, string> = {
  investigations: "Investigations",
  evidence: "Evidence",
  traces: "Agent traces",
  policies: "Policy & approvals",
  evaluation: "Evaluation",
  audit: "Audit & cases",
  cases: "Cases",
};

function currentSection(pathname: string): string {
  const first = pathname.split("/").filter(Boolean)[0];
  return first ? (PAGE_TITLES[first] ?? "Overview") : "Overview";
}

export function Layout() {
  const { session } = useSession();
  const {
    datasets,
    activeDataset,
    activeDatasetId,
    selectDataset,
    audit,
    auditError,
    lastRefresh,
    refresh,
    loading,
    error,
    zone,
    setZone,
  } = useWorkspace();
  const location = useLocation();
  const auditState = auditError
    ? { label: "Audit unavailable", tone: "unknown" as const }
    : audit
      ? audit.integrity === "valid" && audit.safe_for_mutations
        ? { label: "Audit chain valid", tone: "success" as const }
        : { label: "Audit blocks mutations", tone: "danger" as const }
      : { label: "Audit unchecked", tone: "unknown" as const };

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <aside className="sidebar" aria-label="Workbench sidebar">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true">
            AG
          </span>
          <div>
            <p className="brand__name">Agent Security</p>
            <p className="brand__product">Workbench</p>
          </div>
        </div>
        <p className="sidebar__label">Analysis</p>
        <nav aria-label="Primary navigation">
          <ul className="nav">
            {NAV_ITEMS.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) => `nav__link${isActive ? " nav__link--active" : ""}`}
                >
                  <span className="nav__index" aria-hidden="true">
                    {item.index}
                  </span>
                  <span>{item.label}</span>
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="sidebar__footer">
          <p className="sidebar__label">Boundary</p>
          <p>
            Local synthetic workbench. No external case writes, shell, secrets, or network tools.
          </p>
          <p className="sidebar__session">
            Operator <span className="mono">{session?.operator_id ?? "unknown"}</span>
          </p>
          <p className="sidebar__session-note">Identity is a local session, not verified human identity.</p>
        </div>
      </aside>

      <div className="main-column">
        <header className="topbar">
          <div className="topbar__path">
            <span className="muted">Workbench</span>
            <span aria-hidden="true">/</span>
            <strong>{currentSection(location.pathname)}</strong>
          </div>
          <div className="topbar__controls">
            <div className="dataset-picker">
              <label htmlFor="dataset-select" className="dataset-picker__label">
                Dataset
              </label>
              <select
                id="dataset-select"
                value={activeDatasetId ?? ""}
                onChange={(event) => selectDataset(event.target.value)}
                disabled={loading || datasets.length === 0}
              >
                {datasets.length === 0 ? <option value="">No dataset loaded</option> : null}
                {datasets.map((dataset) => (
                  <option value={dataset.id} key={dataset.id}>
                    {dataset.name} ({dataset.event_count ?? 0} events)
                  </option>
                ))}
              </select>
            </div>
            <span className="scope-badge" title="Every record in this scope is synthetic.">
              Synthetic data
            </span>
            <span className="runtime-badge">Scripted runtime</span>
            <div className="topbar__audit">
              <StatusBadge status={auditState.label} explicit={auditState.tone} />
            </div>
            <div className="zone-toggle" role="group" aria-label="Timestamp display">
              <button
                type="button"
                aria-pressed={zone === "utc"}
                className={zone === "utc" ? "is-active" : ""}
                onClick={() => setZone("utc")}
              >
                UTC
              </button>
              <button
                type="button"
                aria-pressed={zone === "local"}
                className={zone === "local" ? "is-active" : ""}
                onClick={() => setZone("local")}
              >
                Local
              </button>
            </div>
            <Button type="button" size="sm" variant="quiet" onClick={refresh} aria-label="Refresh all visible data">
              Refresh
            </Button>
          </div>
        </header>

        <div className="scope-line">
          <div>
            <span className="scope-line__key">Scope</span>
            {activeDataset ? (
              <>
                <span className="scope-line__value">{activeDataset.name}</span>
                <span className="scope-line__sep">·</span>
                <span>{activeDataset.scenario_key}</span>
                <span className="scope-line__sep">·</span>
                <span className="mono" title={activeDataset.manifest_sha256}>
                  manifest {activeDataset.manifest_sha256.slice(0, 12)}
                </span>
                <span className="scope-line__sep">·</span>
                <span>{activeDataset.event_count ?? 0} events</span>
              </>
            ) : (
              <span className="scope-line__value">No dataset selected</span>
            )}
          </div>
          <div className="scope-line__meta">
            {error ? <span className="text-danger">Workspace refresh failed</span> : null}
            <span>{relativeTime(lastRefresh)}</span>
            {session ? (
              <span title={session.expires_at}>Session active</span>
            ) : null}
          </div>
        </div>

        {error ? (
          <div className="workspace-error" role="alert">
            <strong>Workspace data could not be refreshed.</strong> {error}
          </div>
        ) : null}

        <main id="main-content" className="main-content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
