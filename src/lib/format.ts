export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

// Cached because constructing Intl.DateTimeFormat per call is expensive, and
// this runs once per visible file row on every render.
let cachedDateFormatter: Intl.DateTimeFormat | null = null;

function getDateFormatter(): Intl.DateTimeFormat {
  if (!cachedDateFormatter) {
    cachedDateFormatter = new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }
  return cachedDateFormatter;
}

export function formatDate(unixSeconds?: number | null): string {
  if (!unixSeconds) return "-";
  return getDateFormatter().format(new Date(unixSeconds * 1000));
}

export function parentPath(path: string): string {
  const normalized = path.replace(/\/+$/, "");
  const idx = normalized.lastIndexOf("/");
  if (idx <= 0) return "/";
  return normalized.substring(0, idx);
}

/** "3d 4h", "5h 12m", "42s" */
export function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${Math.floor(seconds)}s`;
}

/** Bytes per second as "1.2 MB/s" */
export function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(Math.max(0, Math.round(bytesPerSecond)))}/s`;
}
