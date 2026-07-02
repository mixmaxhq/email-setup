# email-setup — repo card

> A map, not a manual. Keep it ~1 screen; point to detail, don't inline it.

## What it is

Published npm library (`email-setup`) of async utilities that check a domain's email-authentication DNS records — SPF, DKIM, and DMARC — via Node's `dns.resolveTxt`.

## serves

role: SPF/DKIM/DMARC domain-config check utilities — exports `spfSetup`, `hasSPFSender`, `spfRecordResolvesWithinDnsLookupsLimit`, `hasDKIMRecordForSelector`, `dmarcSetup`, plus `SETUP` / `INVALID` / `NOT_SETUP` result constants.
referenced-by: [app]

## Code map

- Entry shim (Node-version dispatch to `dist/` vs `src/`) -> index.js
- All check functions + exports -> src/index.js
- Tests (Jest, stubbed `dns`) -> src/index.test.js
- CI (shared reusable workflow) -> .github/workflows/ci.yml

## Conventions

- Package manager: npm (package-lock.json).
- Test framework: Jest (`jest`, with jest-junit reporter + coverage).
- Build: Babel (`babel src -d dist/node`) on `prepublishOnly`; `index.js` loads `dist/` for Node < 7.6.0, else `src/`.
- CI: GitHub Actions via `mixmaxhq/github-workflows-public` `checks.yml`.
- Publish: semantic-release (`@mixmaxhq/semantic-release-config`) — public npm, not `private`.
- DNS parsing deps: spf-parse, spf-master, dmarc-parse.

## Run / test

- `npm install`
- `npm test` — run Jest
- `npm run lint` — ESLint
- `npm run ci` — lint + test with coverage

## Load the matching domain card

- Cross-cutting library — load the consuming capability's card, not a domain-* for this repo.
