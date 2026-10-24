import net from "node:net";

export function normalizeNetworkIp(value) {
  let candidate = String(value || "").trim();
  const mappedIpv4 = candidate.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mappedIpv4 && net.isIP(mappedIpv4[1]) === 4) candidate = mappedIpv4[1];
  return net.isIP(candidate) ? candidate : "";
}

export function isLoopbackIp(value) {
  const candidate = normalizeNetworkIp(value);
  if (candidate === "::1") return true;
  return net.isIP(candidate) === 4 && candidate.startsWith("127.");
}

function lastForwardedIp(value) {
  const raw = Array.isArray(value) ? value.join(",") : String(value || "");
  const entries = raw.split(",").map((entry) => entry.trim()).filter(Boolean);
  return entries.length ? normalizeNetworkIp(entries.at(-1)) : "";
}

export function requestIp(req = {}) {
  const socketIp = normalizeNetworkIp(req?.socket?.remoteAddress);
  if (!isLoopbackIp(socketIp)) return socketIp;

  const forwardedIp = lastForwardedIp(req?.headers?.["x-forwarded-for"]);
  if (forwardedIp) return forwardedIp;

  const realIp = lastForwardedIp(req?.headers?.["x-real-ip"]);
  return realIp || socketIp;
}
