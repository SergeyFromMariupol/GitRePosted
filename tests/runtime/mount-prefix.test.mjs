import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath, pathToFileURL } from "node:url";

const application = process.env.GITREPOSTED_RUNTIME_SOURCE || fileURLToPath(new URL("../../payload/src/", import.meta.url));
const { publicBaseInfo, publicLocalPath, publicPathPrefix, renderPublicHtml } = await import(pathToFileURL(path.join(application, "src/public-base.js")));

test("the external base accepts only the project mount or legacy root and rejects normalized path tricks", () => {
  for (const origin of ["https://shared.example", "https://203.0.113.10", "http://localhost:3010"]) {
    assert.deepEqual(publicBaseInfo(origin), { baseUrl: origin, pathPrefix: "" });
    assert.deepEqual(publicBaseInfo(origin + "/"), { baseUrl: origin, pathPrefix: "" });
    assert.deepEqual(publicBaseInfo(origin + "/GitRePosted"), { baseUrl: origin + "/GitRePosted", pathPrefix: "/GitRePosted" });
    assert.equal(publicLocalPath(origin + "/GitRePosted", "/api/session?refresh=1"), "/GitRePosted/api/session?refresh=1");
  }
  assert.equal(publicPathPrefix(undefined), "");
  assert.equal(publicLocalPath("https://standalone.example", "/control/"), "/control/");
  for (const suffix of ["/GitPosted", "/gitreposted", "/GitRePosted/", "/other/../GitRePosted", "/%47itRePosted", "/GitRePosted%2f", "//GitRePosted", "/GitRePosted?", "/GitRePosted#", "/GitRePosted?x=1", "/GitRePosted#fragment", "\\GitRePosted"]) {
    assert.throws(() => publicBaseInfo("https://shared.example" + suffix), /PUBLIC_BASE_URL/);
  }
  for (const base of ["", "javascript:bad", "https://user:password@shared.example/GitRePosted", "https://shared.example/\nGitRePosted"]) assert.throws(() => publicBaseInfo(base));
  assert.throws(() => publicLocalPath("https://shared.example", "//foreign.example/api"));
});

test("real landing and admin HTML route local assets and links through the configured mount", () => {
  for (const name of ["index.html", "landing.html"]) {
    const source = fs.readFileSync(path.join(application, "public", name), "utf8");
    const root = renderPublicHtml(source, "https://shared.example");
    assert.equal(root, source);
    const mounted = renderPublicHtml(source, "https://shared.example/GitRePosted");
    assert.match(mounted, /name="gitreposted-base-path" content="\/GitRePosted"/);
    assert.doesNotMatch(mounted, /\b(?:src|href)="\/(?!GitRePosted\/|\/)/);
    assert.match(mounted, /src="\/GitRePosted\/assets\/reposted-logo.png"/);
    if (name === "index.html") assert.match(mounted, /src="\/GitRePosted\/app.js\?/);
    else {
      assert.match(mounted, /href="\/GitRePosted\/control\/"/);
      assert.match(mounted, /href="#main"/);
      assert.match(mounted, /href="https:\/\/github.com\/SergeyFromMariupol\/GitRePosted"/);
    }
  }
});

test("browser API and landing status use the emitted mount rather than the shared host root", async () => {
  const source = fs.readFileSync(path.join(application, "public/app.js"), "utf8");
  const apiSource = source.slice(0, source.indexOf("function passkeySupported("));
  for (const prefix of ["", "/GitRePosted"]) {
    const requests = [];
    const context = vm.createContext({
      document: { querySelector: () => ({ content: prefix }) },
      localStorage: { getItem: () => null },
      fetch: async (url) => { requests.push(url); return { ok: true, json: async () => ({ ok: true }) }; }
    });
    vm.runInContext(apiSource, context);
    await vm.runInContext('api("/api/passkeys/register/options", {method:"POST"})', context);
    assert.deepEqual(requests, [prefix + "/api/passkeys/register/options"]);
    assert.equal(vm.runInContext('localUrl("/assets/max.png")', context), prefix + "/assets/max.png");
    assert.throws(() => vm.runInContext('localUrl("//foreign.example")', context));
    const landing = fs.readFileSync(path.join(application, "public/landing.html"), "utf8");
    const script = /<script>\s*([\s\S]*?)<\/script>/.exec(landing)[1];
    requests.length = 0;
    await vm.runInNewContext(script, {
      document: { querySelector: () => ({ content: prefix }), querySelectorAll: () => [] }, URL,
      fetch: async (url) => { requests.push(url); return { json: async () => ({}) }; }
    });
    assert.deepEqual(requests, [prefix + "/api/public-status"]);
  }
  // Every direct browser request must use the same path helper, including restart polling.
  assert.equal([...source.matchAll(/\bfetch\(/g)].length, [...source.matchAll(/\bfetch\(localUrl\(/g)].length);
  assert.doesNotMatch(source, /src="\/assets\//);
});
