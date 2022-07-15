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

// Create a lookup table for our stubbed `dns.resolveTXT` call to query.
const domainSPFResults = {
  'no.spf.com': { err: dnsErr(dns.NODATA) },
  'invalid.spf.com': {
    err: null,
    value: [['v=spf1 redirect=foo.com redirect=bar.com ~all']]
  },
  'valid.spf.com': { err: null, value: [['v=spf1 include:_spf.google.com -all']] },
  'google._domainkey.no.spf.com': { err: dnsErr(dns.NODATA) },
  'google._domainkey.valid.spf.com': { err: null, value: [['a value']] },
  '_dmarc.no.spf.com': { err: dnsErr(dns.NOTFOUND) },
  '_dmarc.invalid.spf.com': { err: null, value: [['invalid dmarc']] },
  '_dmarc.valid.spf.com': { err: null, value: [['v=DMARC1; p=none']] },
  'google._domainkey.missing-dkim.com': { err: dnsErr(dns.SERVFAIL) },
  'valid_with_include_and_a.spf.com': { err: null, value: [['v=spf1 include:valid_with_a.spf.com a:valid_with_only_all.spf.com -all']] },
  'valid_with_a.spf.com': { err: null, value: [['v=spf1 a:valid_with_only_all.spf.com -all']] },
  'valid_with_only_all.spf.com': { err: null, value: [['v=spf1 mx -all']] },
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

  it('should return \'invalid\' for a domain with an invalid SPF record', async () => {
    expect(await emailSetup.spfSetup('invalid.spf.com')).toBe(INVALID);
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

  it('should return \'invalid\' for a domain with an invalid DMARC record', async () => {
    expect(await emailSetup.dmarcSetup('invalid.spf.com')).toBe(INVALID);
  });

  it('should return \'setup\' for a domain with a valid DMARC record', async () => {
    expect(await emailSetup.dmarcSetup('valid.spf.com')).toBe(SETUP);
  });
});
