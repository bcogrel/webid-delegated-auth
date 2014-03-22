"""
    Delegated Authentication client-side tools
"""
from urlparse import urlparse, parse_qs, urlunparse
from urllib import urlencode, unquote, quote_plus
import dateutil.parser
from datetime import datetime
from M2Crypto import BIO, RSA, EVP
from base64 import b64decode
from .exceptions import InvalidCallbackURLError, InvalidServiceURLError
from .exceptions import IncompleteAuthURLError, InvalidSignatureError
from .exceptions import ExpiredAuthURLError, UnsyncClockError
from string import replace, ljust


class DelegatedAuthClient(object):
    """
        Tools for interacting with a remote authentication service.
        Generates request url and validates the returned auth urls.
    """

    def __init__(self, service_pub_key, service_url,
                 token_expiration=60,
                 negative_duration_tolerance=30,
                 require_https_client=True):
        """
            Token expiration and negative duration in seconds
        """

        # SSL
        bio = BIO.MemoryBuffer(service_pub_key)
        rsa = RSA.load_pub_key_bio(bio)
        self._service_pkey = EVP.PKey()
        self._service_pkey.assign_rsa(rsa)
        # Currently, only RSA-SHA1 is supported
        self._service_pkey.reset_context(md='sha1')

        if not service_url.startswith("https"):
            raise InvalidServiceURLError("HTTPS is required")
        self._service_url = service_url
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

    def validate(self, auth_url):
        """ Returns the WebID if the token is valid
            Raise exceptions otherwise
        """
        parsed_u = urlparse(auth_url)

        # Cleaned query dict (no systematic list for attr.)
        query_dict = dict((k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(parsed_u.query).iteritems())
        print query_dict


        #TODO: check if there is a returned error
        # See https://auth.my-profile.eu/

        try:
            # Extracts and removes
            webid = query_dict.pop('webid')
            sig = query_dict.pop('sig')
            ts = query_dict.pop('ts')

        except KeyError as e:
            raise IncompleteAuthURLError(e)

        # Optional parameter: referer
        if query_dict.has_key('referer'):
            query_dict.pop('referer')

        # Shrink URL by removing the query
        u = list(parsed_u)
        u[4] = urlencode(query_dict)
        partial_url = urlunparse(u)

        # Check the signature
        sep = "&" if "?" in partial_url else "?"
        test_url = "%s%swebid=%s&ts=%s" % (partial_url, sep, quote_plus(webid), quote_plus(ts))
        # May raise an InvalidSignatureError
        self._check_signature(test_url, sig)

        #Check timestamp (less critical than fake cert)
        # May raise an ExpiredAuthURLError
        self._check_timestamp(ts)

        return unquote(webid)

    def _check_signature(self, test_url, sig):
        """
            TODO: to be cleaned!
        """
        # Seen in https://github.com/WebIDauth/WebIDDelegatedAuth/blob/master/lib/Authentication_URL.php#130
        signature = ljust(replace(sig, '-', '+').replace('_', '/'),
                          len(sig) + len(sig) % 4, "=")
        signature = b64decode(signature)

        self._service_pkey.verify_init()
        self._service_pkey.verify_update(test_url)
        valid = (self._service_pkey.verify_final(signature) == 1)

        if not valid:
            raise InvalidSignatureError(test_url)
        return

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

