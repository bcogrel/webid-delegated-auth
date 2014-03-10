"""
    Delegated Authentication client-side tools
"""
from urlparse import urlparse, parse_qs, urlunparse
from urllib import urlencode, unquote, quote
from .exceptions import InvalidCallbackURLError, InvalidServiceURLError,
from .exceptions import IncompleteAuthURLError

class DelegatedAuthClient(object):
    """
        Tools for interacting with a remote authentication service.
        Generates request url and validates the returned auth urls.
    """

    def __init__(self, service_pub_key, service_url,
                 token_expiration = 60,
                 require_https_client=True):
        """
            Token expiration in seconds
        """
        self._service_pub_key = service_pub_key
        if not service_url.startswith("https"):
            raise InvalidServiceURLError("HTTPS is required")
        self._service_url = service_url
        self._token_expiration = token_expiration
        self._require_https_client = require_https_client

    def gen_request_url(self, callback_url):
        """ Returns an URI to which the user should be redirected """
        if self._require_https_client and not callback_url.startswith("https"):
            raise InvalidCallbackURLError(callback_url)

        u = urlparse(self._service_url)
        query_dict = parse_qs(u.query)
        query_dict['authreqissuer'] = quote(callback_url)

        # UGLY trick!
        u._replace(query=urlencode(query_dict))
        return urlunparse(u)

    def validate(self, auth_url):
        """ Returns the WebID if the token is valid
            Raise exceptions otherwise
        """

        u = urlparse(auth_url)
        query_dict = parse_qs(u.query)

        # Shrink URL by removing the query
        u._replace(query='')
        partial_url = urlunparse(u)
        u = None

        try:
            webid = query_dict['webid']
            sig = query_dict['sig']
            ts = query_dict['ts']

        except KeyError as e:
            raise IncompleteAuthURLError(e)

        #Check signature
        test_url = "%s?webid=%s&ts=%s" % (partial_url, webid, ts)
        #TODO: signed it

        #Check timestamp (less critical than fake cert)
        #TODO: to continue

        return unquote(webid)


