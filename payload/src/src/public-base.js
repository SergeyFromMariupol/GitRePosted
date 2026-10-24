// The external mount is configuration, never an untrusted proxy header.
export function publicBaseInfo(value) {
  const source = String(value || "").trim();
  let url;
  try { url = new URL(source); } catch { /* Report one bounded configuration error below. */ }
  const rawPath = /^https?:\/\/[^/?#]+(\/[^?#]*)?$/i.exec(source)?.[1] || "";
  if (!url || !/^https?:\/\/[^/?#]+(?:\/[^?#]*)?$/i.test(source)
    || /[\x00-\x20\x7f\\]/.test(source) || !["http:", "https:"].includes(url.protocol)
    || !url.hostname || url.username || url.password || url.search || url.hash
    || !["", "/", "/GitRePosted"].includes(rawPath) || url.pathname !== (rawPath || "/")) {
    throw new Error("PUBLIC_BASE_URL must contain an HTTP(S) origin optionally followed by /GitRePosted.");
  }
  const pathPrefix = rawPath === "/GitRePosted" ? rawPath : "";
  return { baseUrl: url.origin + pathPrefix, pathPrefix };
}

export function publicPathPrefix(value) {
  return value ? publicBaseInfo(value).pathPrefix : "";
}

export function publicLocalPath(value, route) {
  if (typeof route !== "string" || !route.startsWith("/") || route.startsWith("//")) {
    throw new Error("An application route must start with a single slash.");
  }
  return publicPathPrefix(value) + route;
}

export function renderPublicHtml(source, value) {
  const prefix = publicPathPrefix(value);
  return String(source)
    .replace('<meta name="gitreposted-base-path" content="">', `<meta name="gitreposted-base-path" content="${prefix}">`)
    .replace(/\b(src|href)="\/(?!\/)/g, `$1="${prefix}/`);
}
