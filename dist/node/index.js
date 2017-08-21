

/**
 * Checks whether a domain has setup a valid SPF record.
 *
 * @param {string} domain The domain to check the SPF record for.
 * @returns {Promise} Resolves to true if the domain has a valid SPF record,
 *   false otherwise.
 */
let spfSetup = (() => {
  var _ref = _asyncToGenerator(function* (domain) {
    let spfRecord = yield _getSPFRecord(domain);

    if (!spfRecord) return NOT_SETUP;else if (!spfRecord.valid) return INVALID;
    return SETUP;
  });

  return function spfSetup(_x) {
    return _ref.apply(this, arguments);
  };
})();

/**
 * Checks whether a domain has setup a valid SPF record that allows for the
 * provided sender to send emails. Note that this only checks top level
 * includes at the moment.
 *
 * @param {string} domain The domain to check the SPF record for.
 * @returns {Promise} Resolves to true if the domain has a valid SPF record and
 *   allows the provided sender to send emails, false otherwise.
 */


let hasSPFSender = (() => {
  var _ref2 = _asyncToGenerator(function* (domain, sender) {
    let spfRecord = yield _getSPFRecord(domain);
    if (!spfRecord || !spfRecord.valid) return false;

    return !!_.findWhere(spfRecord.mechanisms, {
      prefixdesc: 'Pass',
      type: 'include',
      value: sender
    });
  });

  return function hasSPFSender(_x2, _x3) {
    return _ref2.apply(this, arguments);
  };
})();

/**
 * Returns the parsed SPF record, null if there was no record found.
 *
 * @param {string} domain The domain to retrieve the SPF record for.
 * @returns {Promise} Resolves to the parsed SPF record, null if there isn't
 *   an SPF record found.
 */


let _getSPFRecord = (() => {
  var _ref3 = _asyncToGenerator(function* (domain) {
    let records = yield _getDNSTXTRecords(domain);

    // `resolveTxt` always returns an array of records, so we need to
    // identify the SPF record.
    let rawSPFRecord = _.chain(records).flatten().find(function (val) {
      return val.startsWith('v=spf1');
    }).value();
    if (!rawSPFRecord) {
      return null;
    }

    return spfParse(rawSPFRecord);
  });

  return function _getSPFRecord(_x4) {
    return _ref3.apply(this, arguments);
  };
})();

/**
 * Returns the TXT records for the domain.
 *
 * @param {string} domain The domain to retrieve the TXT records for.
 * @returns {Promise} Resolves to the retrieved SPF records, or null if none
 *   are found.
 */


let _getDNSTXTRecords = (() => {
  var _ref4 = _asyncToGenerator(function* (domain) {
    let dnsProm = deferred();
    dns.resolveTxt(domain, dnsProm.defer());

    try {
      let records = yield dnsProm;
      return records;
    } catch (err) {
      if (_.contains(NO_DNS_RECORD, err.code)) {
        return null;
      } else {
        throw err;
      }
    }
  });

  return function _getDNSTXTRecords(_x5) {
    return _ref4.apply(this, arguments);
  };
})();

/**
 * Checks whether a domain has setup a valid DKIM record for the given selector.
 *
 * @param {string} domain The domain to check the DKIM record for.
 * @param {string} selector The selector to check for the DKIM record under.
 * @returns {Promise} Resolves to true if the domain has a DKIM record setup,
 *   false otherwise.
 */


let hasDKIMRecordForSelector = (() => {
  var _ref5 = _asyncToGenerator(function* (domain, selector) {
    let dnsProm = deferred();

    // NOTE: this could also be a CNAME, but only in node 8 was resolveAny
    // introduced, and this is functional enough for now (for all providers not
    // using setups similar to EasyDKIM).
    dns.resolveTxt(`${selector}._domainkey.${domain}`, dnsProm.defer());

    try {
      let records = yield dnsProm;
      return _.chain(records).flatten().compact().size().value() > 0 ? SETUP : NOT_SETUP;
    } catch (err) {
      if (_.contains(NO_DNS_RECORD, err.code)) {
        return NOT_SETUP;
      } else {
        throw err;
      }
    }
  });

  return function hasDKIMRecordForSelector(_x6, _x7) {
    return _ref5.apply(this, arguments);
  };
})();

/**
 * Retrieves the parsed DMARC record for the given domain.
 *
 * @param {string} domain The domain to check the DMARC record for.
 * @returns {Promise} Resolves to the parsed DMARC record if it exists, null
 *   otherwise.
 */


let _getDMARCRecord = (() => {
  var _ref6 = _asyncToGenerator(function* (domain) {
    let records = yield _getDNSTXTRecords(`_dmarc.${domain}`);

    // `resolveTxt` always returns an array of records, so we need to
    // identify the DMARC record - it should be the only one.
    let rawDMARCRecord = _.chain(records).flatten().first().value();
    if (!rawDMARCRecord) {
      return null;
    }

    return dmarcParse(rawDMARCRecord);
  });

  return function _getDMARCRecord(_x8) {
    return _ref6.apply(this, arguments);
  };
})();

/**
 * Checks whether a domain has setup a valid DMARC record.
 *
 * @param {string} domain The domain to check the DMARC record for.
 * @returns {Promise} Resolves to true if the domain has a valid DMARC record,
 *   false otherwise.
 */


let dmarcSetup = (() => {
  var _ref7 = _asyncToGenerator(function* (domain) {
    let dmarcRecord = yield _getDMARCRecord(domain);
    if (!dmarcRecord) return NOT_SETUP;
    return !_.isEmpty(dmarcRecord.tags) ? SETUP : INVALID;
  });

  return function dmarcSetup(_x9) {
    return _ref7.apply(this, arguments);
  };
})();

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

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

// DNS error codes to use to determine if a record doesn't exist versus
// an error with retrieving a DNS record (i.e. a network issue).
const NO_DNS_RECORD = [dns.NOTFOUND, dns.NODATA];

// Constants to export to allow users to compare setup values.
const NOT_SETUP = 'not_setup',
      INVALID = 'invalid',
      SETUP = 'setup';

module.exports = {
  spfSetup,
  hasSPFSender,
  hasDKIMRecordForSelector,
  dmarcSetup,

  // Export constants for value comparison.
  SETUP,
  INVALID,
  NOT_SETUP
};