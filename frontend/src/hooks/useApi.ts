import { useCallback, useEffect, useState } from "react";
import { apiRequest, errorMessage } from "../api/client";
import { useWorkspace } from "../state/WorkspaceContext";

interface AsyncResource<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  refreshing: boolean;
  refreshedAt: Date | null;
  reload: () => void;
}

/**
 * Loads one same-origin API resource. A failed refresh keeps the previously
 * loaded data visible and exposes the error separately (stale-but-visible).
 */
export function useApi<T>(path: string | null, localKey = ""): AsyncResource<T> {
  const { refreshKey } = useWorkspace();
  const resourceKey = path;
  const [nonce, setNonce] = useState(0);
  const attemptKey = JSON.stringify([path, localKey, refreshKey, nonce]);
  const [resource, setResource] = useState<{
    key: string | null;
    attemptKey: string;
    data: T | null;
    error: string | null;
    refreshedAt: Date | null;
  } | null>(null);

  useEffect(() => {
    if (path === null) {
      return;
    }
    const controller = new AbortController();
    apiRequest<T>(path, { signal: controller.signal })
      .then((result) => {
        if (controller.signal.aborted) return;
        setResource({ key: resourceKey, attemptKey, data: result, refreshedAt: new Date(), error: null });
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setResource((current) => ({ key: resourceKey, attemptKey,
          data: current?.key === resourceKey ? current.data : null,
          refreshedAt: current?.key === resourceKey ? current.refreshedAt : null,
          error: errorMessage(cause) }));
      });
    return () => controller.abort();
  }, [path, resourceKey, attemptKey]);

  const reload = useCallback(() => setNonce((value) => value + 1), []);
  const current = path !== null && resource?.key === resourceKey ? resource : null;
  const pending = path !== null && resource?.attemptKey !== attemptKey;
  return {
    data: current?.data ?? null,
    error: !pending ? current?.error ?? null : null,
    loading: pending && !current?.data,
    refreshing: pending && current?.data != null,
    refreshedAt: current?.refreshedAt ?? null,
    reload,
  };
}
