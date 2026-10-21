import {
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";
import { Link } from "react-router-dom";
import { shortHash } from "../lib/format";

export type BadgeTone = "neutral" | "info" | "success" | "warning" | "danger" | "unknown";

const BADGE_LABELS: Record<string, string> = {
  ALLOW: "ALLOW",
  BLOCK: "BLOCK",
  REQUIRE_APPROVAL: "REQUIRE APPROVAL",
  PENDING: "PENDING",
  SUCCEEDED: "SUCCEEDED",
  FAILED: "FAILED",
  NOT_STARTED: "NOT STARTED",
  RUNNING: "RUNNING",
  WAITING_APPROVAL: "WAITING FOR APPROVAL",
  COMPLETED: "COMPLETED",
  CANCELLED: "CANCELLED",
  CONSUMED: "CONSUMED",
  REJECTED: "REJECTED",
  EXPIRED: "EXPIRED",
  INVALIDATED: "INVALIDATED",
  REVIEW: "REVIEW",
  LOW: "LOW",
  UNKNOWN: "UNKNOWN",
  OPEN: "OPEN",
  REVIEWED: "REVIEWED",
  CLOSED: "CLOSED",
  valid: "VALID",
  invalid: "INVALID",
  unverifiable: "UNVERIFIABLE",
  checkpoint_matched: "CHECKPOINT MATCHED",
  checkpoint_mismatch: "CHECKPOINT MISMATCH",
  unanchored: "UNANCHORED",
  ok: "OK",
  failed: "FAILED",
  PASS: "PASS",
  FAIL: "FAIL",
  ABSTAINED: "ABSTAINED",
  MISSING: "MISSING",
  ERROR: "ERROR",
  UNLABELED: "UNLABELED",
  TP: "TRUE POSITIVE",
  FP: "FALSE POSITIVE",
  TN: "TRUE NEGATIVE",
  FN: "FALSE NEGATIVE",
};

export function badgeTone(label: string, explicit?: BadgeTone): BadgeTone {
  if (explicit) {
    return explicit;
  }
  const key = label.toUpperCase();
  if (["ALLOW", "SUCCEEDED", "COMPLETED", "CONSUMED", "VALID", "CHECKPOINT MATCHED", "OK", "PASS", "TP", "TN"].includes(key)) {
    return "success";
  }
  if (["BLOCK", "FAILED", "INVALID", "CHECKPOINT MISMATCH", "FAIL", "FN", "ERROR"].includes(key)) {
    return "danger";
  }
  if (["REQUIRE_APPROVAL", "PENDING", "WAITING_APPROVAL", "REVIEW", "WARNING", "FP"].includes(key)) {
    return "warning";
  }
  if (["REJECTED", "EXPIRED", "INVALIDATED", "CANCELLED"].includes(key)) {
    return "neutral";
  }
  if (["UNKNOWN", "ABSTAINED", "UNANCHORED", "MISSING", "UNLABELED", "UNVERIFIABLE"].includes(key)) {
    return "unknown";
  }
  return "info";
}

export function Badge({
  children,
  tone,
  label,
}: {
  children?: ReactNode;
  tone?: BadgeTone;
  label?: string;
}) {
  const text = children ?? label ?? "";
  const resolved = badgeTone(String(text), tone);
  return (
    <span className={`badge badge--${resolved}`}>
      <span className="badge__dot" aria-hidden="true" />
      {text}
    </span>
  );
}

export function StatusBadge({ status, explicit }: { status: string; explicit?: BadgeTone }) {
  return <Badge tone={explicit}>{BADGE_LABELS[status] ?? status.replaceAll("_", " ")}</Badge>;
}

export function Button({
  variant = "secondary",
  size = "md",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "quiet" | "danger";
  size?: "sm" | "md";
}) {
  return (
    <button
      className={`button button--${variant} button--${size} ${className}`.trim()}
      {...props}
    />
  );
}

export function LinkButton({
  to,
  children,
  variant = "secondary",
  size = "md",
}: {
  to: string;
  children: ReactNode;
  variant?: "primary" | "secondary" | "quiet";
  size?: "sm" | "md";
}) {
  return (
    <Link className={`button button--${variant} button--${size}`} to={to}>
      {children}
    </Link>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="page-header__copy">
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        {description ? <div className="page-header__description">{description}</div> : null}
      </div>
      {actions ? <div className="page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function Section({
  title,
  description,
  actions,
  children,
  className = "",
  id,
}: {
  title?: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
}) {
  return (
    <section className={`panel ${className}`.trim()} id={id}>
      {title || description || actions ? (
        <div className="panel__header">
          <div>
            {title ? <h2>{title}</h2> : null}
            {description ? <div className="panel__description">{description}</div> : null}
          </div>
          {actions ? <div className="panel__actions">{actions}</div> : null}
        </div>
      ) : null}
      <div className="panel__body">{children}</div>
    </section>
  );
}

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="state-block" role="status">
      <span className="spinner" aria-hidden="true" />
      <div>
        <p className="state-block__title">{label}…</p>
        <p className="muted">Reading the local workbench database.</p>
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="state-block state-block--empty">
      <span className="state-block__mark" aria-hidden="true">
        ∅
      </span>
      <div>
        <p className="state-block__title">{title}</p>
        {children ? <div className="muted">{children}</div> : null}
        {action ? <div className="state-block__action">{action}</div> : null}
      </div>
    </div>
  );
}

export function ErrorNotice({
  message,
  code,
  requestId,
  action,
}: {
  message: string;
  code?: string | null;
  requestId?: string | null;
  action?: ReactNode;
}) {
  return (
    <div className="notice notice--danger" role="alert">
      <div>
        <p className="notice__title">Request failed</p>
        <p>{message}</p>
        {code || requestId ? (
          <p className="notice__meta mono">
            {code ?? "ERROR"}
            {requestId ? ` · request ${requestId}` : ""}
          </p>
        ) : null}
      </div>
      {action ? <div>{action}</div> : null}
    </div>
  );
}

export function Notice({
  tone = "info",
  title,
  children,
}: {
  tone?: "info" | "warning" | "danger" | "success";
  title?: string;
  children: ReactNode;
}) {
  return (
    <div className={`notice notice--${tone}`} role={tone === "danger" ? "alert" : undefined}>
      <div>
        {title ? <p className="notice__title">{title}</p> : null}
        <div>{children}</div>
      </div>
    </div>
  );
}

export function Field({
  label,
  hint,
  htmlFor,
  children,
  optional,
}: {
  label: string;
  hint?: ReactNode;
  htmlFor?: string;
  children: ReactNode;
  optional?: boolean;
}) {
  return (
    <div className="field">
      <label className="field__label" htmlFor={htmlFor}>
        {label}
        {optional ? <span className="field__optional">Optional</span> : null}
      </label>
      {children}
      {hint ? <p className="field__hint">{hint}</p> : null}
    </div>
  );
}

export function Definition({
  items,
  columns = 2,
}: {
  items: Array<{ term: ReactNode; description: ReactNode; mono?: boolean }>;
  columns?: 1 | 2 | 3;
}) {
  return (
    <dl className={`definition definition--cols-${columns}`}>
      {items.map((item, index) => (
        <div className="definition__item" key={index}>
          <dt>{item.term}</dt>
          <dd className={item.mono ? "mono" : undefined}>{item.description}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };
  return (
    <Button type="button" size="sm" variant="quiet" onClick={copy} aria-live="polite">
      {copied ? "Copied" : label}
    </Button>
  );
}

export function Hash({ value, label }: { value: string | null | undefined; label?: string }) {
  if (!value) {
    return <span className="muted">none</span>;
  }
  return (
    <span className="hash">
      {label ? <span className="hash__label">{label}</span> : null}
      <code title={value}>{shortHash(value)}</code>
      <CopyButton value={value} label="Copy full" />
    </span>
  );
}

export function CodeBlock({ children, label }: { children: string; label?: string }) {
  return (
    <div className="code-block">
      {label ? <p className="code-block__label">{label}</p> : null}
      <pre>
        <code>{children}</code>
      </pre>
    </div>
  );
}

export function LastUpdated({
  at,
  refreshing,
  onRefresh,
  error,
}: {
  at: Date | null;
  refreshing: boolean;
  onRefresh?: () => void;
  error?: string | null;
}) {
  return (
    <div className="last-updated">
      <span className={error ? "last-updated__error" : "muted"}>
        {refreshing ? "Refreshing…" : at ? `Last updated ${at.toLocaleTimeString()}` : "Not loaded"}
        {error ? " · refresh failed; showing previous data" : ""}
      </span>
      {onRefresh ? (
        <Button type="button" size="sm" variant="quiet" onClick={onRefresh}>
          Refresh
        </Button>
      ) : null}
    </div>
  );
}
