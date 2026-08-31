const emailSetup = require('./index');
const dns = require('dns');

const { INVALID, NOT_SETUP, SETUP } = emailSetup;

/**
 * Helper for creating DNS specific errors with the given `errCode`.
 *
 * @param {string} errCode The `errCode` to attach to the error.
 * @returns {Error} The synthesized error to return.
 */
function dnsErr(errCode) {
  const err = new Error('dns error');
  err.code = errCode;
  return err;
}

/**
 * Splits a record the way DNS does, into chunks of at most 255 bytes.
 *
 * @param {string} record The record to split.
 * @returns {Array<string>} The record's chunks, as `dns.resolveTxt` returns them.
 */
function chunkRecord(record) {
  const chunks = [];
  for (let i = 0; i < record.length; i += 255) {
    chunks.push(record.slice(i, i + 255));
  }
  return chunks;
}

// A DMARC record with more than one `rua`/`ruf` address runs past 255 bytes,
// so DNS hands it back in chunks that have to be rejoined before parsing.
const LONG_DMARC_RECORD = 'v=DMARC1; p=reject; sp=reject; pct=100; fo=1; ri=86400; ' +
  'rua=mailto:dmarc-aggregate-reports@deliverability.example.com,mailto:dmarc-aggregate-archive@reporting.example.com; ' +
  'ruf=mailto:dmarc-forensic-reports@deliverability.example.com,mailto:dmarc-forensic-archive@reporting.example.com';

// Likewise for an SPF record listing enough netblocks. Here the truncation is
// visible in the parsed result: the `include` sits past the chunk boundary.
const LONG_SPF_RECORD = (() => {
  const terms = ['v=spf1'];
  for (let i = 0; i < 14; i++) terms.push(`ip4:198.51.100.${i}/32`);
  terms.push('include:_spf.google.com', '-all');
  return terms.join(' ');
})();

// A domain-verification token, of the kind that lives alongside - or instead
// of - a DMARC record under `_dmarc`. This is what SUP-474 was parsing as if
// it were a DMARC policy.
const STRAY_TXT_RECORD = 'google-site-verification=Bo1kXcRfR1nSJ7YQnGPQZpKr0k1x9uLq0m8dQeNb1cE';

// Create a lookup table for our stubbed `dns.resolveTXT` call to query.
const domainSPFResults = {
  'no.spf.com': { err: dnsErr(dns.NODATA) },
  'invalid.spf.com': {
    err: null,
    value: [['v=spf1 redirect=foo.com redirect=bar.com ~all']]
  },
  'invalid_without_all_mechanism.spf.com': {
    err: null,
    value: [['v=spf1 include:_spf.google.com']]
  },
  'invalid_with_all_mechanism_misplaced.spf.com': {
    err: null,
    value: [['v=spf1 -all include:_spf.google.com']]
  },
  'valid.spf.com': { err: null, value: [['v=spf1 include:_spf.google.com -all']] },
  'google._domainkey.no.spf.com': { err: dnsErr(dns.NODATA) },
  'google._domainkey.valid.spf.com': { err: null, value: [['a value']] },
  '_dmarc.no.spf.com': { err: dnsErr(dns.NOTFOUND) },
  '_dmarc.invalid.spf.com': { err: null, value: [['invalid dmarc']] },
  '_dmarc.valid.spf.com': { err: null, value: [['v=DMARC1; p=none']] },
  // The organizational domain of every `*.spf.com` domain above - looked up
  // as the RFC 7489 §6.6.3 fallback whenever the subdomain has no record.
  '_dmarc.spf.com': { err: dnsErr(dns.NOTFOUND) },
  'google._domainkey.missing-dkim.com': { err: dnsErr(dns.SERVFAIL) },
  'valid_with_include_and_a.spf.com': { err: null, value: [['v=spf1 include:valid_with_a.spf.com a:valid_with_only_all.spf.com -all']] },
  'valid_with_a.spf.com': { err: null, value: [['v=spf1 a:valid_with_only_all.spf.com -all']] },
  'valid_with_only_all.spf.com': { err: null, value: [['v=spf1 mx -all']] },
  'chunked.spf.com': { err: null, value: [chunkRecord(LONG_SPF_RECORD)] },

  // A stray non-DMARC record published alongside the real one. Listed first so
  // that a resolver handing it back first - which is what made SUP-474
  // intermittent - can't be mistaken for the DMARC record.
  '_dmarc.stray-and-valid.dmarc-test.com': {
    err: null,
    value: [[STRAY_TXT_RECORD], ['v=DMARC1; p=quarantine; rua=mailto:dmarc@dmarc-test.com']]
  },
  // The same stray record, with no DMARC record alongside it.
  '_dmarc.stray-only.dmarc-test.com': { err: null, value: [[STRAY_TXT_RECORD]] },
  // Carries the version tag, but with a value `dmarc-parse` rejects, so it
  // parses to no tags at all: something is published, and it's broken.
  '_dmarc.malformed.dmarc-test.com': { err: null, value: [['v=dmarc1']] },
  '_dmarc.chunked.dmarc-test.com': { err: null, value: [chunkRecord(LONG_DMARC_RECORD)] },
  // The organizational domain shared by the `*.dmarc-test.com` domains above.
  '_dmarc.dmarc-test.com': { err: dnsErr(dns.NOTFOUND) },

  // The domain reported in SUP-474. Verified against production DNS:
  //   dig TXT _dmarc.ext.airbnb.com -> NXDOMAIN
  //   dig +short TXT _dmarc.airbnb.com -> the record below
  // The policy in force for `ext.airbnb.com` is the organizational domain's
  // `sp=reject`, but we were reporting DMARC missing.
  '_dmarc.ext.airbnb.com': { err: dnsErr(dns.NOTFOUND) },
  '_dmarc.airbnb.com': {
    err: null,
    value: [['v=DMARC1;p=reject;sp=reject;pct=100;ruf=mailto:dmarc.forensic@airbnb.com;rua=mailto:dmarc.aggregate@airbnb.com;aspf=r;adkim=r;fo=1;ri=3600']]
  },

  // Neither the subdomain nor its organizational domain publishes a record.
  '_dmarc.mail.no-dmarc-anywhere.com': { err: dnsErr(dns.NOTFOUND) },
  '_dmarc.no-dmarc-anywhere.com': { err: dnsErr(dns.NOTFOUND) },
  '_dmarc.No-DMARC-Anywhere.com': { err: dnsErr(dns.NOTFOUND) },

  // A multi-label public suffix: the organizational domain of
  // `mail.example.co.uk` is `example.co.uk`, not `co.uk`.
  '_dmarc.mail.example.co.uk': { err: dnsErr(dns.NOTFOUND) },
  '_dmarc.example.co.uk': { err: null, value: [['v=DMARC1; p=none; sp=quarantine']] },

  // A resolver failure that isn't "no such record".
  '_dmarc.resolver-error.com': { err: dnsErr('ECONNREFUSED') },
};

beforeEach(() => {
  jest.spyOn(dns, 'resolveTxt').mockImplementation((domain, done) => {
    const val = domainSPFResults[domain];
    if (val) done(val.err, val.value);
    else done(new Error('no such domain'));
  });
});

afterEach(() => {
  jest.restoreAllMocks();
})

describe('spfSetup', () => {
  it('should return \'not_setup\' for a domain with no SPF record', async () => {
    expect(await emailSetup.spfSetup('no.spf.com')).toBe(NOT_SETUP);
  });

  it('should return \'invalid\' for a domain with an invalid SPF record (multiple redirects)', async () => {
    expect(await emailSetup.spfSetup('invalid.spf.com')).toBe(INVALID);
  });

  it('should return \'invalid\' for a domain with an invalid SPF record (no all)', async () => {
    expect(await emailSetup.spfSetup('invalid_without_all_mechanism.spf.com', {
      validations: {
        allMechanismOrRedirectModifierIsPresent: true,
      }
    })).toBe(INVALID);
  });

  it('should return \'invalid\' for a domain with an invalid SPF record (misplaced all)', async () => {
    expect(await emailSetup.spfSetup('invalid_with_all_mechanism_misplaced.spf.com', {
      validations: {
        allMechanismIsTheLast: true,
      }
    })).toBe(INVALID);
  });

  it('should return \'setup\' for a domain with a valid SPF record', async () => {
    expect(await emailSetup.spfSetup('valid.spf.com')).toBe(SETUP);
  });
});

describe('hasSPFSender', () => {
  it('should return false when missing a specific sender', async () => {
    expect(
      await emailSetup.hasSPFSender('valid.spf.com', 'spf.protection.outlook.com')
    ).toBe(false);
  });

  it('should return true when the sender is allowed', async () => {
    expect(await emailSetup.hasSPFSender('valid.spf.com', '_spf.google.com')).toBe(true);
  });

  it('should join a chunked record before looking for the sender', async () => {
    // Guard the fixture: this only exercises anything while the record is long
    // enough for DNS to split it.
    expect(LONG_SPF_RECORD.length).toBeGreaterThan(255);
    expect(chunkRecord(LONG_SPF_RECORD).length).toBe(2);

    // The `include` sits past the 255-byte boundary, so reading only the first
    // chunk loses it.
    expect(await emailSetup.hasSPFSender('chunked.spf.com', '_spf.google.com')).toBe(true);
  });
});

describe('spfRecordResolvesWithinDnsLookupsLimit', () => {
  it('should return false for a domain with no SPF record', async () => {
    expect(await emailSetup.spfRecordResolvesWithinDnsLookupsLimit('no.spf.com', 10000)).toBe(false);
    expect(dns.resolveTxt.mock.calls.length).toBe(1);
  });

  it('should return true for a domain with an invalid SPF record resolving within limit', async () => {
    expect(await emailSetup.spfRecordResolvesWithinDnsLookupsLimit('invalid.spf.com', 10)).toBe(true);
    expect(dns.resolveTxt.mock.calls.length).toBe(1);
  });

  it('should return false when it does not resolve within DNS lookups limit', async () => {
    expect(await emailSetup.spfRecordResolvesWithinDnsLookupsLimit('valid_with_include_and_a.spf.com', 1)).toBe(false);
    expect(dns.resolveTxt.mock.calls.length).toBe(2);
  });

  it('should return true when it resolves within DNS lookups limit', async () => {
    expect(await emailSetup.spfRecordResolvesWithinDnsLookupsLimit('valid_with_include_and_a.spf.com', 2)).toBe(true);
    expect(dns.resolveTxt.mock.calls.length).toBe(2);
  });
});

describe('hasDKIMRecordForSelector', () => {
  it('should return \'not_setup\' for domains w/ TXT records at the selector', async () => {
    expect(await emailSetup.hasDKIMRecordForSelector('no.spf.com', 'google')).toBe(NOT_SETUP);
  });

  it('should return \'not_setup\' for domains w/ TXT records at the selector', async () => {
    expect(await emailSetup.hasDKIMRecordForSelector('missing-dkim.com', 'google')).toBe(NOT_SETUP);
  });

  it('should return \'setup\' for domains w/ TXT records at the selector', async () => {
    expect(await emailSetup.hasDKIMRecordForSelector('valid.spf.com', 'google')).toBe(SETUP);
  });
});

describe('dmarcSetup', () => {
  it('should return \'not_setup\' for a domain with no DMARC record', async () => {
    expect(await emailSetup.dmarcSetup('no.spf.com')).toBe(NOT_SETUP);
  });

  it('should return \'setup\' for a domain with a valid DMARC record', async () => {
    expect(await emailSetup.dmarcSetup('valid.spf.com')).toBe(SETUP);
  });

  it('should return \'invalid\' for a DMARC record that parses to no tags', async () => {
    expect(await emailSetup.dmarcSetup('malformed.dmarc-test.com')).toBe(INVALID);
  });

  it('should ignore a non-DMARC record published alongside the DMARC record', async () => {
    // SUP-474: we took whichever record the resolver returned first, so a stray
    // verification token under `_dmarc` was parsed as if it were the policy and
    // reported the domain misconfigured.
    expect(await emailSetup.dmarcSetup('stray-and-valid.dmarc-test.com')).toBe(SETUP);
  });

  it('should return \'not_setup\' when only a non-DMARC record is published', async () => {
    // A verification token under `_dmarc` is not a broken DMARC record, it's no
    // DMARC record at all.
    expect(await emailSetup.dmarcSetup('stray-only.dmarc-test.com')).toBe(NOT_SETUP);
    expect(await emailSetup.dmarcSetup('invalid.spf.com')).toBe(NOT_SETUP);
  });

  it('should fall back to the organizational domain for a subdomain', async () => {
    // SUP-474: `ext.airbnb.com` publishes no record of its own, but the
    // `sp=reject` on `airbnb.com` is the policy in force for it (RFC 7489
    // §6.6.3).
    expect(await emailSetup.dmarcSetup('ext.airbnb.com')).toBe(SETUP);
    expect(dns.resolveTxt.mock.calls.map((call) => call[0]))
      .toEqual(['_dmarc.ext.airbnb.com', '_dmarc.airbnb.com']);
  });

  it('should resolve the organizational domain across a multi-label public suffix', async () => {
    expect(await emailSetup.dmarcSetup('mail.example.co.uk')).toBe(SETUP);
    // Not `_dmarc.co.uk`, which is a public suffix rather than a domain
    // anybody can publish a policy on.
    expect(dns.resolveTxt.mock.calls.map((call) => call[0]))
      .toEqual(['_dmarc.mail.example.co.uk', '_dmarc.example.co.uk']);
  });

  it('should return \'not_setup\' when neither the subdomain nor its organizational domain has a record', async () => {
    expect(await emailSetup.dmarcSetup('mail.no-dmarc-anywhere.com')).toBe(NOT_SETUP);
    expect(dns.resolveTxt.mock.calls.map((call) => call[0]))
      .toEqual(['_dmarc.mail.no-dmarc-anywhere.com', '_dmarc.no-dmarc-anywhere.com']);
  });

  it('should not look past an organizational domain that has no record', async () => {
    // RFC 7489 specifies exactly two lookups, so an apex domain gets one.
    expect(await emailSetup.dmarcSetup('no-dmarc-anywhere.com')).toBe(NOT_SETUP);
    expect(dns.resolveTxt.mock.calls.length).toBe(1);
  });

  it('should not treat a mixed-case apex domain as its own subdomain', async () => {
    // `psl.get` lower-cases what it returns, so comparing it against the
    // domain as given would send us looking the same name up twice.
    expect(await emailSetup.dmarcSetup('No-DMARC-Anywhere.com')).toBe(NOT_SETUP);
    expect(dns.resolveTxt.mock.calls.length).toBe(1);
  });

  it('should join a chunked DMARC record before parsing it', async () => {
    // Guard the fixture: this only exercises anything while the record is long
    // enough for DNS to split it.
    expect(LONG_DMARC_RECORD.length).toBeGreaterThan(255);
    expect(chunkRecord(LONG_DMARC_RECORD).length).toBe(2);

    // Note that truncation isn't visible in this verdict today - it drops the
    // trailing `ruf` tag, and `dmarcSetup` only asks whether any tag parsed.
    // The assertion guards the joining for callers that read the tags, and the
    // lookup count confirms the joined record matched the version tag rather
    // than falling through to the organizational domain.
    expect(await emailSetup.dmarcSetup('chunked.dmarc-test.com')).toBe(SETUP);
    expect(dns.resolveTxt.mock.calls.length).toBe(1);
  });

  it('should propagate a resolver error that is not a missing record', async () => {
    await expect(emailSetup.dmarcSetup('resolver-error.com')).rejects.toThrow('dns error');
  });
});
