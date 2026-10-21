import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { apiRequest, errorMessage } from "../api/client";
import type { AuditReport, Dataset, DatasetList } from "../api/types";
import { useSession } from "./SessionContext";

export type TimeZoneMode = "utc" | "local";

interface WorkspaceContextValue {
  datasets: Dataset[];
  activeDataset: Dataset | null;
  activeDatasetId: string | null;
  selectDataset: (id: string) => void;
  loading: boolean;
  error: string | null;
  audit: AuditReport | null;
  auditError: string | null;
  refreshKey: number;
  lastRefresh: Date | null;
  refresh: () => void;
  importSample: () => Promise<void>;
  importingSample: boolean;
  zone: TimeZoneMode;
  setZone: (zone: TimeZoneMode) => void;
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);
const DATASET_STORAGE_KEY = "agentguard.dataset";
const ZONE_STORAGE_KEY = "agentguard.timezone";

function readStorage(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Persistence is optional; the visible scope still applies in memory.
  }
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const { session } = useSession();
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [audit, setAudit] = useState<AuditReport | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [importingSample, setImportingSample] = useState(false);
  const [zone, setZoneState] = useState<TimeZoneMode>(
    readStorage(ZONE_STORAGE_KEY) === "local" ? "local" : "utc",
  );

  useEffect(() => {
    if (!session) {
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    apiRequest<DatasetList>("/datasets", { signal: controller.signal })
      .then((result) => {
        setDatasets(result.items);
        setActiveId((current) => {
          if (current && result.items.some((item) => item.id === current)) {
            return current;
          }
          const stored = readStorage(DATASET_STORAGE_KEY);
          if (stored && result.items.some((item) => item.id === stored)) {
            return stored;
          }
          const sample = result.items.find((item) => item.is_sample === 1);
          return sample?.id ?? result.items[0]?.id ?? null;
        });
        setLastRefresh(new Date());
      })
      .catch((cause: unknown) => {
        if (!controller.signal.aborted) {
          setError(errorMessage(cause));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });
    apiRequest<AuditReport>("/audit/summary", { signal: controller.signal })
      .then((result) => {
        setAudit(result);
        setAuditError(null);
      })
      .catch((cause: unknown) => {
        if (!controller.signal.aborted) {
          setAuditError(errorMessage(cause));
        }
      });
    return () => controller.abort();
  }, [session, refreshKey]);

  useEffect(() => {
    if (activeId) {
      writeStorage(DATASET_STORAGE_KEY, activeId);
    }
  }, [activeId]);

  const selectDataset = useCallback((id: string) => setActiveId(id), []);

  const refresh = useCallback(() => {
    setRefreshKey((value) => value + 1);
  }, []);

  const importSample = useCallback(async () => {
    setImportingSample(true);
    setError(null);
    try {
      await apiRequest("/datasets/sample/import", { method: "POST" });
      setRefreshKey((value) => value + 1);
    } catch (cause) {
      setError(errorMessage(cause));
      throw cause;
    } finally {
      setImportingSample(false);
    }
  }, []);

  const setZone = useCallback((next: TimeZoneMode) => {
    setZoneState(next);
    writeStorage(ZONE_STORAGE_KEY, next);
  }, []);

  const activeDataset = useMemo(
    () => datasets.find((item) => item.id === activeId) ?? null,
    [datasets, activeId],
  );

  const value = useMemo(
    () => ({
      datasets,
      activeDataset,
      activeDatasetId: activeId,
      selectDataset,
      loading,
      error,
      audit,
      auditError,
      refreshKey,
      lastRefresh,
      refresh,
      importSample,
      importingSample,
      zone,
      setZone,
    }),
    [
      datasets,
      activeDataset,
      activeId,
      selectDataset,
      loading,
      error,
      audit,
      auditError,
      refreshKey,
      lastRefresh,
      refresh,
      importSample,
      importingSample,
      zone,
      setZone,
    ],
  );

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const value = useContext(WorkspaceContext);
  if (!value) {
    throw new Error("useWorkspace must be used inside WorkspaceProvider");
  }
  return value;
}
