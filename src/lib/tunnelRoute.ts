import type { PortForwardRule } from "./api";

export type ForwardType = PortForwardRule["forward_type"];

export const FORWARD_TYPES: {
  value: ForwardType;
  flag: string;
  label: string;
  description: string;
}[] = [
  {
    value: "local",
    flag: "-L",
    label: "Local",
    description: "Open a port on this computer that reaches a service on the server's network.",
  },
  {
    value: "remote",
    flag: "-R",
    label: "Remote",
    description: "Open a port on the server that reaches a service on this computer.",
  },
  {
    value: "dynamic",
    flag: "-D",
    label: "Dynamic (SOCKS)",
    description: "SOCKS proxy on this computer: apps choose any destination, reached from the server.",
  },
];

export const forwardTypeInfo = (type: ForwardType) =>
  FORWARD_TYPES.find((t) => t.value === type) ?? FORWARD_TYPES[0];

export function formatEndpoint(host: string, port: number): string {
  const h = host.trim() || "127.0.0.1";
  return h.includes(":") ? `[${h}]:${port}` : `${h}:${port}`;
}

export function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  return h === "" || h === "localhost" || h === "::1" || h.startsWith("127.");
}

export interface TunnelRoute {
  listenLabel: string;
  listen: string;
  targetLabel: string;
  /** null for dynamic forwards: each app picks its own destination */
  target: string | null;
}

/**
 * Stored rules keep the client-side endpoint in local_* and the server-side
 * endpoint in remote_* for every type (see TunnelSpec::from_rule in Rust),
 * so which one listens depends on the type.
 */
export function describeRoute(rule: PortForwardRule): TunnelRoute {
  const local = formatEndpoint(rule.local_address, rule.local_port);
  const remote = formatEndpoint(rule.remote_address, rule.remote_port);
  switch (rule.forward_type) {
    case "remote":
      return { listenLabel: "Listen (server)", listen: remote, targetLabel: "To (this computer)", target: local };
    case "dynamic":
      return { listenLabel: "SOCKS proxy", listen: local, targetLabel: "To", target: null };
    default:
      return { listenLabel: "Listen (this computer)", listen: local, targetLabel: "To (via server)", target: remote };
  }
}
