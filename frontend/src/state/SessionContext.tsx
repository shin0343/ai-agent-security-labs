import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { ApiError, apiRequest, errorMessage, getCsrfToken, setStoredCsrfToken } from "../api/client";
import type { SessionInfo } from "../api/types";

interface SessionContextValue {
  session: SessionInfo | null;
  checking: boolean;
  exchanging: boolean;
  error: string | null;
  exchange: (code: string) => Promise<void>;
  clearError: () => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [checking, setChecking] = useState(true);
  const [exchanging, setExchanging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    apiRequest<SessionInfo>("/session", {
      signal: controller.signal,
      suppressUnauthorizedEvent: true,
    })
      .then((result) => {
        setStoredCsrfToken(result.csrf_token);
        setSession(result);
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        if (cause instanceof ApiError && cause.status === 401) {
          setSession(null);
          return;
        }
        setError(errorMessage(cause));
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setChecking(false);
        }
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const onUnauthorized = () => {
      setStoredCsrfToken(null);
      setSession(null);
      setError("The local operator session expired. Enter a new bootstrap code from the server console.");
    };
    window.addEventListener("agentguard:unauthorized", onUnauthorized);
    return () => window.removeEventListener("agentguard:unauthorized", onUnauthorized);
  }, []);

  const exchange = useCallback(async (code: string) => {
    setExchanging(true);
    setError(null);
    try {
      const result = await apiRequest<SessionInfo>("/session/exchange", {
        method: "POST",
        body: { code },
        suppressUnauthorizedEvent: true,
      });
      setStoredCsrfToken(result.csrf_token);
      setSession(result);
    } catch (cause) {
      setStoredCsrfToken(null);
      setError(errorMessage(cause));
      throw cause;
    } finally {
      setExchanging(false);
    }
  }, []);

  const clearError = useCallback(() => setError(null), []);

  const value = useMemo(
    () => ({ session, checking, exchanging, error, exchange, clearError }),
    [session, checking, exchanging, error, exchange, clearError],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (!value) {
    throw new Error("useSession must be used inside SessionProvider");
  }
  return value;
}

export function hasCsrfToken(): boolean {
  return getCsrfToken() !== null;
}
