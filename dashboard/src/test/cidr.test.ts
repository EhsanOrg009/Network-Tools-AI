import { describe, expect, it } from "vitest";
import { ipInCidr, isValidCidr, isValidIp, maskToPrefix } from "../lib/cidr";

describe("ipInCidr (IPv4)", () => {
  it("matches containment for /24", () => {
    expect(ipInCidr("192.168.1.10", "192.168.1.0/24")).toBe(true);
    expect(ipInCidr("192.168.1.254", "192.168.1.0/24")).toBe(true);
    expect(ipInCidr("192.168.2.10", "192.168.1.0/24")).toBe(false);
  });
  it("matches various prefixes", () => {
    expect(ipInCidr("10.0.0.5", "10.0.0.0/8")).toBe(true);
    expect(ipInCidr("11.0.0.5", "10.0.0.0/8")).toBe(false);
    expect(ipInCidr("10.233.68.48", "10.233.68.0/25")).toBe(true);
    expect(ipInCidr("10.233.68.200", "10.233.68.0/25")).toBe(false);
    expect(ipInCidr("172.16.47.1", "172.16.47.1/32")).toBe(true);
    expect(ipInCidr("172.16.47.2", "172.16.47.1/32")).toBe(false);
  });
  it("treats bare IP cidr as /32", () => {
    expect(ipInCidr("192.168.1.1", "192.168.1.1")).toBe(true);
    expect(ipInCidr("192.168.1.2", "192.168.1.1")).toBe(false);
  });
});

describe("ipInCidr (IPv6, compressed and full)", () => {
  it("matches compressed addresses", () => {
    expect(ipInCidr("fe80::1", "fe80::/64")).toBe(true);
    expect(ipInCidr("fe80::2", "fe80::1/128")).toBe(false);
    expect(ipInCidr("2001:db8:1234:5678::dead:beef", "2001:db8:1234:5678::/64")).toBe(true);
    expect(ipInCidr("2001:db8:1234:5679::1", "2001:db8:1234:5678::/64")).toBe(false);
  });
  it("matches full-form addresses", () => {
    expect(ipInCidr("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::/32")).toBe(true);
    expect(ipInCidr("2001:0db9::1", "2001:db8::/32")).toBe(false);
  });
  it("never mixes families", () => {
    expect(ipInCidr("192.168.1.1", "fe80::/64")).toBe(false);
    expect(ipInCidr("fe80::1", "192.168.1.0/24")).toBe(false);
  });
});

describe("input validation", () => {
  it("rejects garbage instead of crashing", () => {
    expect(ipInCidr("", "192.168.1.0/24")).toBe(false);
    expect(ipInCidr("not-an-ip", "192.168.1.0/24")).toBe(false);
    expect(ipInCidr("192.168.1.1", "")).toBe(false);
    expect(ipInCidr("192.168.1.1", "not-a-cidr")).toBe(false);
    expect(ipInCidr("192.168.1.1", "192.168.1.0/33")).toBe(false);
  });
  it("isValidIp / isValidCidr", () => {
    expect(isValidIp("10.0.0.1")).toBe(true);
    expect(isValidIp("::1")).toBe(true);
    expect(isValidIp("999.1.1.1")).toBe(false);
    expect(isValidCidr("10.0.0.0/8")).toBe(true);
    expect(isValidCidr("fe80::/10")).toBe(true);
    expect(isValidCidr("10.0.0.0")).toBe(true); // bare IP
    expect(isValidCidr("10.0.0.0/33")).toBe(false);
  });
  it("maskToPrefix converts dotted masks", () => {
    expect(maskToPrefix("255.255.255.0")).toBe(24);
    expect(maskToPrefix("255.255.0.0")).toBe(16);
    expect(maskToPrefix("garbage")).toBeNull();
  });
});
