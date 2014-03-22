"""
    Common functions
"""
from urllib import quote_plus
from .exceptions import IncompleteAuthURLError


def extract_signed_url(auth_url):
    """
        Removes the tail after the sig parameter value.
    """
    sig_pos = auth_url.find('sig=')
    if sig_pos == -1:
        raise IncompleteAuthURLError(auth_url)

    signed_url = auth_url[: sig_pos - 1]
    return signed_url


def gen_signed_url(partial_url, webid, ts):
    sep = "&" if "?" in partial_url else "?"
    return "%s%swebid=%s&ts=%s" % (partial_url, sep, quote_plus(webid), quote_plus(ts))