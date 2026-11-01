/**
 * Runtime validation of backend responses. The dashboard never renders an
 * unvalidated payload: a shape mismatch becomes a visible error state, not a
 * white page. These guards are deliberately structural (no type assertions
 * without a runtime check).
 */

import type {
  EffectiveDiscoveryScope,
  NetworksResponse,
  NetworkObservationRow,
} from "./types";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/** Structural guard for GET /api/admin/v1/networks. */
export function parseNetworksResponse(data: unknown): NetworksResponse {
  if (!isRecord(data)) throw new TypeError("پاسخ networks شیء JSON نیست.");
  if (!Array.isArray(data.observations)) {
    throw new TypeError("پاسخ networks فاقد observations است.");
  }
  const scopeRaw = data.effective_scope;
  if (!isRecord(scopeRaw)) {
    throw new TypeError("پاسخ networks فاقد effective_scope است.");
  }
  const observations: NetworkObservationRow[] = data.observations.filter(
    (o): o is NetworkObservationRow =>
      isRecord(o) && typeof o.agent_id === "string" && typeof o.cidr === "string",
  );
  const effective_scope: EffectiveDiscoveryScope = {
    configured_cidrs: asStringArray(scopeRaw.configured_cidrs),
    authorized_targets: asStringArray(scopeRaw.authorized_targets),
    auto_discovered: Array.isArray(scopeRaw.auto_discovered)
      ? scopeRaw.auto_discovered.filter(
          (a): a is EffectiveDiscoveryScope["auto_discovered"][number] =>
            isRecord(a) && typeof a.cidr === "string",
        )
      : [],
    auto_discovery_enabled: scopeRaw.auto_discovery_enabled === true,
    note: typeof scopeRaw.note === "string" ? scopeRaw.note : undefined,
  };
  return { observations, effective_scope };
}
