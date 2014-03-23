"""
    Delegated Authentication client-side tools
"""
from urlparse import urlparse, parse_qs, urlunparse
from urllib import urlencode, unquote
import dateutil.parser
from datetime import datetime
from M2Crypto import BIO, RSA, EVP
from base64 import urlsafe_b64decode
from .exceptions import *
from string import ljust


def extract_signed_url(auth_url):
    """
        Removes the tail after the sig parameter value.
    """
    sig_pos = auth_url.find('sig=')
    if sig_pos == -1:
        raise IncompleteAuthURLError(auth_url)

    signed_url = auth_url[: sig_pos - 1]
    return signed_url


class DelegatedAuthClient(object):
    """
        Tools for interacting with a remote authentication service.
        Generates request url and validates the returned auth urls.
    """

    def __init__(self, service_pub_key, service_url,
                 token_expiration=60,
                 negative_duration_tolerance=-30,
                 require_https_client=True):
        """
            Token expiration and negative duration in seconds
        """
        if not service_url.startswith("https"):
            raise InvalidServiceURLError("HTTPS is required")
        self._service_url = service_url

        # SSL
        bio = BIO.MemoryBuffer(service_pub_key)
        rsa = RSA.load_pub_key_bio(bio)
        self._service_pkey = EVP.PKey()
        self._service_pkey.assign_rsa(rsa)
        # Currently, only RSA-SHA1 is supported
        self._service_pkey.reset_context(md='sha1')

        self._token_expiration = token_expiration
        # Tolerance to negative duration due to un-sync clocks
        self._negative_duration_tolerance = negative_duration_tolerance
        self._require_https_client = require_https_client

    def gen_request_url(self, callback_url):
        """ Returns an URI to which the user should be redirected """
        if self._require_https_client and not callback_url.startswith("https"):
            raise InvalidCallbackURLError(callback_url)

        parsed_u = urlparse(self._service_url)
        query_dict = parse_qs(parsed_u.query)
        query_dict['authreqissuer'] = callback_url

        u = list(parsed_u)
        u[4] = urlencode(query_dict)
        return urlunparse(u)

    def check(self, auth_url):
        """ Returns the WebID if the token is valid
            Raise exceptions otherwise
        """
        parsed_u = urlparse(auth_url)

        # Cleaned query dict (no systematic list for attr.)
        query_dict = dict((k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(parsed_u.query).iteritems())

        try:
            sig = query_dict['sig']
        except KeyError as e:
            raise IncompleteAuthURLError(e)

        signed_url = extract_signed_url(auth_url)

        # Check the signature
        # May raise an InvalidSignatureError
        self._check_signature(signed_url, sig)


        # Raise a specific exception if an error
        # has been declared in the URI
        self._check_returned_exception(signed_url)

        # If no declared error
        try:
            # Extracts and removes
            webid = query_dict['webid']
            ts = query_dict['ts']

        except KeyError as e:
            raise IncompleteAuthURLError(e)

        #Check timestamp (less critical than fake cert)
        # May raise an ExpiredAuthURLError
        self._check_timestamp(ts)

        return unquote(webid)

    def _check_signature(self, signed_url, sig):
        # Decodes the URL-safe-without-padding encoded signature
        signature = urlsafe_b64decode(ljust(sig, len(sig) + len(sig) % 4, "="))

        self._service_pkey.verify_init()
        self._service_pkey.verify_update(signed_url)
        valid = (self._service_pkey.verify_final(signature) == 1)
        if not valid:
            raise InvalidSignatureError(signed_url)

    def _check_timestamp(self, ts):
        """
            TODO: Audit possible hacks on the ts
        """
        ts = unquote(ts)
        # Fuzzy disable failing in some fields are unknown
        auth_t = dateutil.parser.parse(ts, fuzzy=True)

        current_t = datetime.now(auth_t.tzinfo)
        delta = (current_t - auth_t).seconds

        if delta > self._token_expiration:
            raise ExpiredAuthURLError(delta - self._token_expiration)

        if delta < self._negative_duration_tolerance:
            raise UnsyncClockError()

    def _check_returned_exception(self, signed_url):
        """
           If a User auth exception has been returned,
           checks the signature and
           returns a specific exception
        """
        key = 'error='

        if not key in signed_url:
            return

        # Robust approach (prevents a double "?" bad format)
        error_pos = signed_url.find(key)
        next_rel_sep_pos = signed_url[error_pos:].find("&")
        if next_rel_sep_pos == -1:
            error = signed_url[error_pos+len(key):]
        else:
            error = signed_url[error_pos+len(key): error_pos + next_rel_sep_pos]

        if error == NO_CLAIM_CODE:
            raise NoClaimException()
        elif error == NO_CERT_CODE:
            raise NoCertException()
        elif error == CERT_NO_OWNERSHIP_CODE:
            raise CertNoOwnershipException()
        elif error == REJECTED_CLAIM_CODE:
            raise RejectedClaimException()
        elif error == CERT_WITHOUT_URI_CODE:
            raise CertWithoutUriException()
        elif error == EXPIRED_CERT_CODE:
            raise ExpiredUserCertException()
        elif error == UNDECLARED_CERT_CODE:
            raise UndeclaredCertException()
        elif error == NOT_A_WEBID_CODE:
            raise NotAWebIDException()
        elif error == IDP_ERROR_CODE:
            raise IdPException()
        # Unknown code
        else:
            raise UserAuthException(error)





