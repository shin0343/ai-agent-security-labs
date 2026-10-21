import type { AuditReport } from "./types";

export const API_PREFIX = "/api/v1";
const CSRF_STORAGE_KEY = "agentguard.csrf";

export interface ApiErrorBody {
  code?: string;
  message?: string;
  request_id?: string;
  details?: Record<string, unknown>;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly details: Record<string, unknown>;

  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    super(body?.message ?? fallback);
    this.name = "ApiError";
    this.status = status;
    this.code = body?.code ?? "REQUEST_FAILED";
    this.requestId = body?.request_id ?? null;
    this.details = body?.details ?? {};
  }
}

export function getStoredCsrfToken(): string | null {
  try {
    return sessionStorage.getItem(CSRF_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setStoredCsrfToken(token: string | null): void {
  try {
    if (token) {
      sessionStorage.setItem(CSRF_STORAGE_KEY, token);
    } else {
      sessionStorage.removeItem(CSRF_STORAGE_KEY);
    }
  } catch {
    // Session storage can be unavailable in hardened browser contexts. The
    // in-memory copy below still supports the current page.
  }
  memoryCsrfToken = token;
}

let memoryCsrfToken: string | null = getStoredCsrfToken();

export function getCsrfToken(): string | null {
  return memoryCsrfToken;
}

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  suppressUnauthorizedEvent?: boolean;
}

function isMutation(method: string): boolean {
  return method !== "GET";
}

async function readError(response: Response): Promise<ApiError> {
  let body: ApiErrorBody | null = null;
  try {
    const parsed: unknown = await response.json();
    if (parsed && typeof parsed === "object") {
      body = parsed as ApiErrorBody;
    }
  } catch {
    body = null;
  }
  return new ApiError(response.status, body, `Request failed with status ${response.status}.`);
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...options.headers,
  };
  const mutation = isMutation(method);
  if (options.body !== undefined || mutation) {
    headers["Content-Type"] = "application/json";
  }
  if (mutation) {
    const csrf = getCsrfToken();
    if (csrf) {
      headers["X-CSRF-Token"] = csrf;
    }
  }
  // Mutations always carry a JSON body. This also makes body-less operations
  // explicit and satisfies the server's JSON-only mutation boundary.
  const body =
    options.body !== undefined ? JSON.stringify(options.body) : mutation ? "{}" : undefined;
  const response = await fetch(`${API_PREFIX}${path}`, {
    method,
    credentials: "same-origin",
    headers,
    body,
    signal: options.signal,
  });
  if (!response.ok) {
    if (response.status === 401 && !options.suppressUnauthorizedEvent) {
      window.dispatchEvent(new CustomEvent("agentguard:unauthorized"));
    }
    throw await readError(response);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  const text = await response.text();
  if (!text) {
    return undefined as T;
  }
  return JSON.parse(text) as T;
}

export function newIdempotencyKey(): string {
  if (typeof crypto.randomUUID === "function") {
    return `ui-${crypto.randomUUID()}`;
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `ui-${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "An unexpected error occurred.";
}

export async function downloadCaseExport(
  caseId: string,
  format: "markdown" | "json" | "csv",
): Promise<{
  filename: string;
  text: string;
  sha256: string;
  auditVerification: AuditReport;
}> {
  const result = await apiRequest<{
    filename: string;
    content: string;
    sha256: string;
    audit_verification: AuditReport;
  }>(`/cases/${encodeURIComponent(caseId)}/exports`, {
    method: "POST",
    body: { format },
  });
  return {
    filename: result.filename,
    text: result.content,
    sha256: result.sha256,
    auditVerification: result.audit_verification,
  };
}

export function saveTextFile(filename: string, text: string, mediaType: string): void {
  const blob = new Blob([text], { type: `${mediaType};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
