// Not const for testing.
var dns = require('dns');

/**
 * This module is a collection of utilities for checking the state
 * of configuration for an email. Currently, it exposes the ability to check
 * SPF, DKIM and DMARC settings.
 */

const _ = require('underscore');
const { deferred } = require('promise-callbacks');
const dmarcParse = require('dmarc-parse');
const psl = require('psl');
const spfParse = require('spf-parse');
const { SpfInspector } = require('spf-master');

// DNS error codes to use to determine if a record doesn't exist versus
// an error with retrieving a DNS record (i.e. a network issue).
//
// Also consider ESERVFAIL as a missing DNS record. Some DNS servers
// seem to prefer that response code instead of NOTFOUND (i.e. the
// nameservers at datagram.com).
const NO_DNS_RECORD = [dns.NOTFOUND, dns.NODATA, dns.SERVFAIL];

// RFC 7489 §6.3 requires a DMARC record to begin with the version tag,
// `v=DMARC1`, and §6.6.3 requires records that don't to be discarded. Anything
// else published at `_dmarc.<domain>` - a domain-verification token, say - is
// not a DMARC record and must not be parsed as one. The tag value ends at the
// first separator, so `v=DMARC10` names a different version and the record is
// discarded - the version tag must be `DMARC1` and nothing more. Tag names are
// case-insensitive; we're lenient about the value's case too, so that a
// record with a mistyped version tag surfaces as `INVALID` (something is
// published at `_dmarc` and it's broken) rather than as `NOT_SETUP`. See
// `dmarcSetup` for the second half of that behaviour.
const DMARC_VERSION_TAG = /^v\s*=\s*DMARC1\s*(?:;|$)/i;

// Warnings from "spf-parse"
const ALL_MECHANISM_IS_NOT_THE_LAST = 'One or more mechanisms were found after the "all" mechanism. These mechanisms will be ignored';
const ALL_AND_REDIRECT_ARE_MISSING = 'SPF strings should always either use an "all" mechanism or a "redirect" modifier to explicitly terminate processing.';

// Constants to export to allow users to compare setup values.
const NOT_SETUP = 'not_setup',
  INVALID = 'invalid',
  SETUP = 'setup';

/**
 * Checks whether a domain has setup a valid SPF record.
 *
 * @param {string} domain The domain to check the SPF record for.
 * @param {object} validations Additional validations.
 * @returns {Promise} Resolves to true if the domain has a valid SPF record,
 *   false otherwise.
 */
async function spfSetup(domain, { validations = {
  allMechanismIsTheLast: false,
  allMechanismOrRedirectModifierIsPresent: false,
} } = {}) {
  let spfRecord = await _getSPFRecord(domain);

  if (!spfRecord) {
    return NOT_SETUP;
  } else if (!spfRecord.valid) {
    return INVALID;
  } else if (spfRecord.messages) {
    const allMechanismIsNotTheLast = spfRecord.messages.some(m => m.message === ALL_MECHANISM_IS_NOT_THE_LAST);
    if (validations.allMechanismIsTheLast && allMechanismIsNotTheLast) {
      return INVALID;
    }

    const allAndRedirectAreMissing = spfRecord.messages.some(m => m.message === ALL_AND_REDIRECT_ARE_MISSING);
    if (validations.allMechanismOrRedirectModifierIsPresent && allAndRedirectAreMissing) {
      return INVALID;
    }
  }
  return SETUP;
}

/**
 * Checks whether a domain has setup a valid SPF record that allows for the
 * provided sender to send emails. Note that this only checks top level
 * includes at the moment.
 *
 * @param {string} domain The domain to check the SPF record for.
 * @returns {Promise} Resolves to true if the domain has a valid SPF record and
 *   allows the provided sender to send emails, false otherwise.
 */
async function hasSPFSender(domain, sender) {
  let spfRecord = await _getSPFRecord(domain);
  if (!spfRecord || !spfRecord.valid) return false;

  return !!_.findWhere(spfRecord.mechanisms, {
    prefixdesc: 'Pass',
    type: 'include',
    value: sender
  });
}

/**
 * Checks whether a domain has a SPF record which could be resolved within
 * the provided number of DNS queries. RFC7208 (SPF specification) requires
 * that the number of mechanisms and modifiers that do DNS lookups must not
 * exceed 10 per SPF check:

 * SPF implementations MUST limit the number of mechanisms and modifiers that
 * do DNS lookups to at most 10 per SPF check, including any lookups caused by
 * the use of the "include" mechanism or the "redirect" modifier.
 * If this number is exceeded during a check, a PermError MUST be returned.
 *
 * The "include", "a", "mx", "ptr", and "exists" mechanisms as well as the
 * "redirect" modifier do count against this limit.
 *
 * The "all", "ip4", and "ip6" mechanisms do not require DNS lookups and
 * therefore do not count against this limit.
 *
 * NOTE: Currently, the underlying library "spf-master" resolves only
 * "include" and "a" mechanisms. This might cause false positive results.
 *
 * @param {string} domain The domain to check the SPF record for.
 * @param {number} limit The max allowed number of DNS lookups.
 * @returns {Promise} Resolves to true if the number of DNS lookups for
 * the SPF record is within limit, false otherwise.
 */
async function spfRecordResolvesWithinDnsLookupsLimit(domain, limit = 10) {
  try {
    const report = await SpfInspector(domain, { maxDepth: limit }, true);

    const numberOfIncludeLookups = report.found.includes.length;
    const numberOfALookups = report.found.domains.length;
    return numberOfIncludeLookups + numberOfALookups <= limit;
  } catch (err) {
    if (_.contains(NO_DNS_RECORD, err.code)) {
      return false;
    } else {
      throw err;
    }
  }
}

/**
 * Returns the parsed SPF record, null if there was no record found.
 *
 * @param {string} domain The domain to retrieve the SPF record for.
 * @returns {Promise} Resolves to the parsed SPF record, null if there isn't
 *   an SPF record found.
 */
async function _getSPFRecord(domain) {
  let records = await _getDNSTXTRecords(domain);

  // `resolveTxt` always returns an array of records, so we need to
  // identify the SPF record.
  let rawSPFRecord = _.find(_joinTXTRecordChunks(records), (val) => val.startsWith('v=spf1'));
  if (!rawSPFRecord) {
    return null;
  }

  return spfParse(rawSPFRecord);
}

/**
 * Joins each TXT record's chunks back into a single string.
 *
 * DNS splits any character-string longer than 255 bytes, so `dns.resolveTxt`
 * hands back an array of chunks per record (`string[][]`). Flattening across
 * records instead of joining within them both truncates a long record to its
 * first chunk and lets the chunks of unrelated records be treated as records
 * in their own right.
 *
 * @param {Array<Array<string>>|null} records The records as returned by `dns.resolveTxt`.
 * @returns {Array<string>} One joined string per record.
 */
function _joinTXTRecordChunks(records) {
  return _.map(records || [], (chunks) => (_.isArray(chunks) ? chunks.join('') : chunks));
}

/**
 * Returns the TXT records for the domain.
 *
 * @param {string} domain The domain to retrieve the TXT records for.
 * @returns {Promise} Resolves to the retrieved SPF records, or null if none
 *   are found.
 */
async function _getDNSTXTRecords(domain) {
  let dnsProm = deferred();
  dns.resolveTxt(domain, dnsProm.defer());

  try {
    let records = await dnsProm;
    return records;
  } catch (err) {
    if (_.contains(NO_DNS_RECORD, err.code)) {
      return null;
    } else {
      throw err;
    }
  }
}

/**
 * Checks whether a domain has setup a valid DKIM record for the given selector.
 *
 * @param {string} domain The domain to check the DKIM record for.
 * @param {string} selector The selector to check for the DKIM record under.
 * @returns {Promise} Resolves to true if the domain has a DKIM record setup,
 *   false otherwise.
 */
async function hasDKIMRecordForSelector(domain, selector) {
  let dnsProm = deferred();

  // NOTE: this could also be a CNAME, but only in node 8 was resolveAny
  // introduced, and this is functional enough for now (for all providers not
  // using setups similar to EasyDKIM).
  dns.resolveTxt(`${selector}._domainkey.${domain}`, dnsProm.defer());

  try {
    let records = await dnsProm;
    return _.chain(records)
      .flatten()
      .compact()
      .size()
      .value() > 0 ? SETUP : NOT_SETUP;
  } catch (err) {
    if (_.contains(NO_DNS_RECORD, err.code)) {
      return NOT_SETUP;
    } else {
      throw err;
    }
  }
}

/**
 * Retrieves the parsed DMARC record published at exactly `_dmarc.<domain>`.
 *
 * `_dmarc.<domain>` may hold TXT records that aren't DMARC records at all, so
 * we select on the version tag rather than taking whichever record the
 * resolver happens to return first.
 *
 * @param {string} domain The domain to check the DMARC record for.
 * @returns {Promise} Resolves to the parsed DMARC record if one is published
 *   at this exact domain, null otherwise.
 */
async function _getDMARCRecordAtDomain(domain) {
  let records = await _getDNSTXTRecords(`_dmarc.${domain}`);

  // If several records carry the version tag the domain is misconfigured;
  // taking the first keeps us reporting "configured", which is the bar this
  // library measures.
  let rawDMARCRecord = _.find(_joinTXTRecordChunks(records), (val) => DMARC_VERSION_TAG.test(val));
  if (!rawDMARCRecord) {
    return null;
  }

  return dmarcParse(rawDMARCRecord);
}

/**
 * Retrieves the parsed DMARC record in force for the given domain.
 *
 * @param {string} domain The domain to check the DMARC record for.
 * @returns {Promise} Resolves to the parsed DMARC record if it exists, null
 *   otherwise.
 */
async function _getDMARCRecord(domain) {
  let dmarcRecord = await _getDMARCRecordAtDomain(domain);
  if (dmarcRecord) return dmarcRecord;

  // RFC 7489 §6.6.3: when a subdomain publishes no DMARC record of its own,
  // the policy in force is the one at its organizational domain - the `sp`
  // tag there (defaulting to `p`) is what governs the subdomain. The RFC
  // specifies exactly these two lookups, so we never walk further up the tree.
  //
  // `psl.get` returns null for input that has no organizational domain (a
  // public suffix itself, say), which means there's no fallback to make. It
  // also lower-cases its result and drops any trailing root label, so we
  // normalise the same way before comparing - otherwise an apex domain written
  // in mixed case looks like a subdomain of itself and gets queried twice.
  const orgDomain = psl.get(domain);
  if (!orgDomain || orgDomain === domain.toLowerCase().replace(/\.$/, '')) return null;

  return _getDMARCRecordAtDomain(orgDomain);
}

/**
 * Checks whether a domain has setup a valid DMARC record, either on the domain
 * itself or - for a subdomain - on its organizational domain.
 *
 * @param {string} domain The domain to check the DMARC record for.
 * @returns {Promise} Resolves to true if the domain has a valid DMARC record,
 *   false otherwise.
 */
async function dmarcSetup(domain) {
  let dmarcRecord = await _getDMARCRecord(domain);
  if (!dmarcRecord) return NOT_SETUP;

  // "dmarc-parse" drops the version tag when its value is not exactly
  // `DMARC1` - a lower-case `v=dmarc1`, say - but it keeps the other tags. So
  // the presence of any tag is not enough: a record without the version tag is
  // published but broken, which is `INVALID`.
  return dmarcRecord.tags && dmarcRecord.tags.v ? SETUP : INVALID;
}


module.exports = {
  spfSetup,
  spfRecordResolvesWithinDnsLookupsLimit,
  hasSPFSender,
  hasDKIMRecordForSelector,
  dmarcSetup,

  // Export constants for value comparison.
  SETUP,
  INVALID,
  NOT_SETUP
};
