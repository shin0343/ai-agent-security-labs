import type { TimeZoneMode } from "../state/WorkspaceContext";

export function formatTimestamp(value: string | null | undefined, zone: TimeZoneMode): string {
  if (!value) {
    return "not recorded";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  if (zone === "utc") {
    const pad = (part: number) => String(part).padStart(2, "0");
    return (
      `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
      `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`
    );
  }
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  }).format(date);
}

export function formatDate(value: string | null | undefined, zone: TimeZoneMode): string {
  if (!value) {
    return "not recorded";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    timeZone: zone === "utc" ? "UTC" : undefined,
  }).format(date);
}

export function relativeTime(from: Date | null, now = new Date()): string {
  if (!from) {
    return "not yet refreshed";
  }
  const seconds = Math.max(0, Math.round((now.getTime() - from.getTime()) / 1000));
  if (seconds < 5) {
    return "just now";
  }
  if (seconds < 60) {
    return `${seconds}s ago`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

export function shortHash(value: string | null | undefined, head = 10, tail = 6): string {
  if (!value) {
    return "none";
  }
  if (value.length <= head + tail + 1) {
    return value;
  }
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

export function numeric(value: number | null | undefined, digits = 3): string {
  if (value === null || value === undefined) {
    return "undefined";
  }
  return Number.isInteger(value) ? String(value) : value.toFixed(digits);
}

export function percent(value: number | null | undefined): string {
  if (value === null || value === undefined) {
    return "undefined";
  }
  return `${(value * 100).toFixed(1)}%`;
}

export function titleCase(value: string): string {
  return value
    .toLowerCase()
    .split("_")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}
