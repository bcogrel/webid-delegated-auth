"""
    Tools for building an auth URL
"""
from datetime import datetime
from urllib import quote_plus
from M2Crypto import RSA, EVP
from base64 import urlsafe_b64encode
from dateutil.tz import tzlocal
from .exceptions import *


def gen_signed_url(auth_req_issuer, webid, ts):
    sep = "&" if "?" in auth_req_issuer else "?"
    return "%s%swebid=%s&ts=%s" % (auth_req_issuer, sep, quote_plus(webid), quote_plus(ts))


def gen_signed_url_with_error(auth_req_issuer, error_code):
    sep = "&" if "?" in auth_req_issuer else "?"
    return "%s%serror=%s" % (auth_req_issuer, sep, error_code)


class URLSigningService:
    """
        Signs Callback URLs
    """

    def __init__(self, private_key, referer_url):
        self.referer_url = referer_url

        self._rsa = RSA.load_key_string(private_key)

    def gen_auth_url(self, webid, auth_req_issuer):
        """ Return an Authorization URL """

        ts = datetime.now(tzlocal()).isoformat()
        print "Timestamp %s " % ts

        signed_url = gen_signed_url(auth_req_issuer, webid, ts)
        sig = self._sign(signed_url)

        return self._gen_returned_url(signed_url, sig)

    def gen_error_url(self, auth_req_issuer, error_code):
        """
            URL for any error code
        """
        signed_url = gen_signed_url_with_error(auth_req_issuer, error_code)
        sig = self._sign(signed_url)

        return self._gen_returned_url(signed_url, sig)

    def gen_no_claim_error_url(self, auth_req_issuer):
        """
            URL for "no claim provided" error.

            Generic
        """
        return self.gen_error_url(auth_req_issuer, NO_CLAIM_CODE)

    def gen_rejected_claim_error_url(self, auth_req_issuer):
        """
            URL for "rejected claim" error.

            Generic
        """
        return self.gen_error_url(auth_req_issuer, REJECTED_CLAIM_CODE)

    def gen_no_cert_error_url(self, auth_req_issuer):
        """
            URL for "no user Cert provided" error
        """
        return self.gen_error_url(auth_req_issuer, NO_CERT_CODE)

    def gen_cert_without_uri_error_url(self, auth_req_issuer):
        """
            URL for "user Cert without URI" error
        """
        return self.gen_error_url(auth_req_issuer, CERT_WITHOUT_URI_CODE)

    def gen_expired_cert_error_url(self, auth_req_issuer):
        """
            URL for "expired cert" error
        """
        return self.gen_error_url(auth_req_issuer, EXPIRED_CERT_CODE)

    def gen_undeclared_cert_error_url(self, auth_req_issuer):
        """
            URL for "undeclared WebID-TLS cert" error
        """
        return self.gen_error_url(auth_req_issuer, UNDECLARED_CERT_CODE)

    def gen_not_a_webid_error_url(self, auth_req_issuer):
        """
            URL for "not a WebID" error
        """
        return self.gen_error_url(auth_req_issuer, NOT_A_WEBID_CODE)

    def gen_idp_error_url(self, auth_req_issuer):
        """
            URL for another Identity Provider error
        """
        return self.gen_error_url(auth_req_issuer, IDP_ERROR_CODE)

    def _gen_returned_url(self, signed_url, sig):
        url = "%s&sig=%s&referer=%s" % (signed_url, sig, self.referer_url)
        return url

    def _sign(self, signed_url):
        """
            Returns the signature of the signed URL.
            SHA1 algorithm
        """
        digest = EVP.MessageDigest('sha1')
        digest.update(signed_url)
        signature = self._rsa.sign(digest.digest())

        # URL-safe encoding and right padding "==" removed
        sig = urlsafe_b64encode(signature).rstrip("=")
        #print "Encoded signature: %s" % sig
        return sig






