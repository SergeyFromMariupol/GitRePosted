# GitRePosted — public contributor instructions

This repository is an installable distribution. Read README.md and the relevant
document in docs/ before changing it. Do not assume that a pre-release has
passed a clean-server or real-provider test unless docs/TESTING.md records it.

- Application code lives in payload/src/. The Node entrypoint is server.js;
  src/ contains ESM modules and public/ contains the active UI.
- bootstrap.sh and lib/provision.py prepare an isolated installation.
- lib/coinstall.py is identical in both projects. It verifies the completed
  sibling installation, validates host/path claims and serializes shared changes.
  Support both installation orders without adopting arbitrary existing sites
  or upgrading the sibling's packages. Keep databases, data, users, services and
  bot tokens separate. Two new rc.8 installations use the fixed /GitPosted and
  /GitRePosted paths on a shared IP, shared domain or different domains.
  lib/gateway.py owns the common nginx routing and root-only registry. One
  authority has one public nginx server and one certificate owner; the other
  project reuses its HTTPS. Scope installer/admin cookies to their app paths.
  A verified older root installation retains the legacy layout and requires
  an explicit different DNS hostname for its sibling; never migrate it silently.
  lib/broker.py owns privileged actions; bin/application.php is its bounded
  child for provider checks and the Node schema CLI. PHP is not the bot runtime.
- Never put real configuration, tokens, keys, database exports, messages,
  sessions, runtime files or logs into this repository or a release.
- Packaging is deny by default: scripts/build.py lists each published file.
  Add an explicit path when introducing a reviewed runtime dependency.
- Preserve durable enqueue, routing snapshots, lease fencing and per-part
  delivery IDs. Unknown provider outcomes must remain uncertain and must not
  be retried automatically. Do not silently change a forward into a copy.
- Tests use offline transports and temporary fixtures. Sending messages,
  changing webhooks or running a real worker needs explicit authorization and
  a named test channel. A health check is not permission to publish.
- Keep workers paused until schema, selected providers and activation checks
  succeed. Never run two instances against copies of the same active state.
- Keep configuration outside the webroot, with restrictive ownership and
  permissions. Secrets go through protected files or stdin, never command-line
  arguments, browser logs or error responses.
- Run the relevant tests in docs/TESTING.md and verify a built manifest. State
  which clean-server and provider checks were actually performed.

The exporter overwrites only a marked generated checkout whose files still
match its inventory. Edit authoritative sources, not a generated checkout.
Do not remove its marker to bypass a refusal or overwrite unrelated work.
