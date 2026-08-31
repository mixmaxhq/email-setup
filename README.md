# email-setup
Collection of utilities for checking email configuration settings.

## Installation
```sh
npm install email-setup
```

## Usage

### SPF

SPF records exist as `TXT` records on a sending domain itself. `spfSetup` allows
us to determine if a domain has a valid SPF record, and `hasSPFSender` allows us
to detemine if a specific sender is allowed to send for the given domain. Note
that `hasSPFSender` currently only support top level `include` detection, it
does not currently resolve the SPF record to determine inclusion at a deeper
level than the top level nor does it support IP based domain resolution querying
at the moment.

#### spfSetup
`spfSetup` will return one of `NOT_SETUP`, `INVALID` or `SETUP`.
```js
const { spfSetup } = require('email-setup');

let isSetup = await spfSetup('foo.com');
```

#### hasSPFSender
`hasSPFSender` returns either `true` or `false` depending on whether the
sender explicitly exists at the top level of the SPF record.
```js
const { hasSPFSender } = require('email-setup');

let isSetup = await hasSPFSender('foo.com', '_spf.google.com');
```

### DKIM

DKIM records do not exist at any predetermined location, as such to check if
a DKIM record is setup for a given system, we need to know the selector to look
for the record under. Once we know that, we can determine whether a DKIM key
has been setup for the given domain at the given selector.

#### hasDKIMRecordForSelector
`hasDKIMRecordForSelector` will return one of `NOT_SETUP`, `INVALID` or `SETUP`.
```js
const { hasDKIMRecordForSelector } = require('email-setup');

let isSetup = await hasDKIMRecordForSelector('foo.com', 'google');
```


### DMARC

DMARC records live as `TXT` records under `_dmarc.<domain>`, alongside whatever
else a domain owner has published there. Only records that begin with the
`v=DMARC1` version tag are DMARC records; anything else under `_dmarc` is
ignored.

A subdomain that publishes no record of its own is governed by the policy on
its organizational domain — its `sp` tag, defaulting to `p`. So when no record
is found on the domain itself, `dmarcSetup` makes one further lookup on the
organizational domain, as RFC 7489 §6.6.3 requires. It never walks further up
the tree than that.

#### dmarcSetup
`dmarcSetup` will return one of `NOT_SETUP`, `INVALID` or `SETUP`.
```js
const { dmarcSetup } = require('email-setup');

let isSetup = await dmarcSetup('foo.com');
```

## Publishing a new version

```
GH_TOKEN=xxx npx semantic-release --no-ci
```
