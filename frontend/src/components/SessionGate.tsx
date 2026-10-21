import { useState, type FormEvent } from "react";
import { useSession } from "../state/SessionContext";
import { Button, Field, Notice } from "./ui";

export function SessionGate() {
  const { exchange, exchanging, error, checking } = useSession();
  const [code, setCode] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLocalError(null);
    if (!code.trim()) {
      setLocalError("Enter the single-use bootstrap code printed by the local server.");
      return;
    }
    try {
      await exchange(code.trim());
    } catch {
      // The session provider exposes the server message.
    }
  };

  if (checking) {
    return (
      <main className="gate">
        <div className="gate__card" role="status">
          <span className="spinner" aria-hidden="true" />
          <p>Checking the local operator session…</p>
        </div>
      </main>
    );
  }

  return (
    <main className="gate">
      <div className="gate__card">
        <div className="gate__brand">
          <span className="brand__mark" aria-hidden="true">
            AG
          </span>
          <div>
            <p className="eyebrow">Local-only security engineering workbench</p>
            <h1>Agent Security Workbench</h1>
          </div>
        </div>
        <p className="gate__intro">
          Evidence-linked investigation, deterministic tool authorization, single-use approval, and
          tamper-evident local audit. All telemetry and effects are synthetic.
        </p>
        <form onSubmit={submit} noValidate>
          <Field
            label="Bootstrap code"
            htmlFor="bootstrap-code"
            hint="The server prints one single-use code at startup. It expires after 10 minutes and is replaced after five failed attempts. The code is never included in browser bundles or URLs."
          >
            <input
              id="bootstrap-code"
              name="bootstrap-code"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              aria-invalid={Boolean(localError)}
              aria-describedby={localError ? "bootstrap-error" : undefined}
              className="mono-input"
            />
          </Field>
          {localError ? (
            <p className="field__error" id="bootstrap-error" role="alert">
              {localError}
            </p>
          ) : null}
          {error ? (
            <Notice tone="danger" title="Session not established">
              {error}
            </Notice>
          ) : null}
          <Button type="submit" variant="primary" disabled={exchanging}>
            {exchanging ? "Establishing session…" : "Open local workbench"}
          </Button>
        </form>
        <div className="gate__boundaries">
          <p>
            <strong>Not a production control.</strong> No multi-user identity, remote access, external
            integrations, real secrets, or host-compromise protection is claimed.
          </p>
          <p>
            The browser uses an HttpOnly SameSite=Strict cookie plus a CSRF token. Mutations require an
            exact loopback origin.
          </p>
        </div>
      </div>
    </main>
  );
}
