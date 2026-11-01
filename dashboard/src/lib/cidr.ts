/**
 * CIDR containment for the topology view — IPv4 and IPv6, compressed or full
 * addresses, any prefix length. Built on ipaddr.js (a well-tested, widely
 * used parser) instead of string comparison.
 */

import { parse } from "ipaddr.js";

export function isValidIp(value: string): boolean {
  try {
    parse(value);
    return true;
  } catch {
    return false;
  }
}

export function isValidCidr(value: string): boolean {
  const raw = (value ?? "").trim();
  const slash = raw.indexOf("/");
  if (slash === -1) return isValidIp(raw);
  try {
    const addr = parse(raw.slice(0, slash));
    const bits = Number(raw.slice(slash + 1));
    if (!Number.isInteger(bits) || bits < 0) return false;
    return bits <= (addr.kind() === "ipv6" ? 128 : 32);
  } catch {
    return false;
  }
}

export function ipVersion(value: string): 4 | 6 | null {
  try {
    const addr = parse(value);
    return addr.kind() === "ipv6" ? 6 : 4;
  } catch {
    return null;
  }
}

/** True when ``ip`` falls inside ``cidr`` (both must parse; version match
 *  required — an IPv4 address is never "inside" an IPv6 network). */
export function ipInCidr(ip: string, cidr: string): boolean {
  const rawIp = (ip ?? "").trim();
  const rawCidr = (cidr ?? "").trim();
  if (!rawIp || !rawCidr) return false;
  try {
    const parsedIp = parse(rawIp);
    const slash = rawCidr.indexOf("/");
    const netAddr = parse(slash === -1 ? rawCidr : rawCidr.slice(0, slash));
    if (parsedIp.kind() !== netAddr.kind()) return false;
    const bits = slash === -1
      ? (netAddr.kind() === "ipv6" ? 128 : 32)
      : Number(rawCidr.slice(slash + 1));
    if (!Number.isInteger(bits) || bits < 0) return false;
    const max = netAddr.kind() === "ipv6" ? 128 : 32;
    if (bits > max) return false;
    // normalize the address into the same family representation
    const ipBytes = toBytes(parsedIp);
    const netBytes = toBytes(netAddr);
    const full = Math.floor(bits / 8);
    for (let i = 0; i < full; i += 1) {
      if (ipBytes[i] !== netBytes[i]) return false;
    }
    const rem = bits % 8;
    if (rem !== 0) {
      const mask = (0xff << (8 - rem)) & 0xff;
      if ((ipBytes[full] & mask) !== (netBytes[full] & mask)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function toBytes(addr: ReturnType<typeof parse>): number[] {
  const kind = addr.kind();
  if (kind === "ipv6") {
    return (addr as unknown as { toByteArray(): number[] }).toByteArray();
  }
  const octets = (addr as unknown as { toByteArray(): number[] }).toByteArray();
  return octets;
}

/** Human-readable prefix length of a subnet mask (e.g. 255.255.255.0 → 24).
 *  Implemented directly over the parsed octets: count contiguous leading
 *  one-bits; a non-contiguous mask is rejected. */
export function maskToPrefix(mask: string): number | null {
  try {
    const addr = parse((mask ?? "").trim());
    if (addr.kind() !== "ipv4") return null;
    const bytes = (addr as unknown as { toByteArray(): number[] }).toByteArray();
    let prefix = 0;
    let done = false;
    for (const byte of bytes) {
      for (let bit = 7; bit >= 0; bit -= 1) {
        const one = (byte >> bit) & 1;
        if (one) {
          if (done) return null; // non-contiguous mask
          prefix += 1;
        } else {
          done = true;
        }
      }
    }
    return prefix;
  } catch {
    return null;
  }
}
