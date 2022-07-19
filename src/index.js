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
const spfParse = require('spf-parse');
const { SpfInspector } = require('spf-master');

// DNS error codes to use to determine if a record doesn't exist versus
// an error with retrieving a DNS record (i.e. a network issue).
//
// Also consider ESERVFAIL as a missing DNS record. Some DNS servers
// seem to prefer that response code instead of NOTFOUND (i.e. the
// nameservers at datagram.com).
const NO_DNS_RECORD = [dns.NOTFOUND, dns.NODATA, dns.SERVFAIL];

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
  let rawSPFRecord = _.chain(records)
    .flatten()
    .find((val) => val.startsWith('v=spf1'))
    .value();
  if (!rawSPFRecord) {
    return null;
  }

  return spfParse(rawSPFRecord);
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
 * Retrieves the parsed DMARC record for the given domain.
 *
 * @param {string} domain The domain to check the DMARC record for.
 * @returns {Promise} Resolves to the parsed DMARC record if it exists, null
 *   otherwise.
 */
async function _getDMARCRecord(domain) {
  let records = await _getDNSTXTRecords(`_dmarc.${domain}`);

  // `resolveTxt` always returns an array of records, so we need to
  // identify the DMARC record - it should be the only one.
  let rawDMARCRecord = _.chain(records)
    .flatten()
    .first()
    .value();
  if (!rawDMARCRecord) {
    return null;
  }

  return dmarcParse(rawDMARCRecord);
}

/**
 * Checks whether a domain has setup a valid DMARC record.
 *
 * @param {string} domain The domain to check the DMARC record for.
 * @returns {Promise} Resolves to true if the domain has a valid DMARC record,
 *   false otherwise.
 */
async function dmarcSetup(domain) {
  let dmarcRecord = await _getDMARCRecord(domain);
  if (!dmarcRecord) return NOT_SETUP;
  return !_.isEmpty(dmarcRecord.tags) ? SETUP : INVALID;
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
