"""
    Common functions
"""
from urllib import quote_plus


def gen_signed_url(partial_url, webid, ts):
    sep = "&" if "?" in partial_url else "?"
    return "%s%swebid=%s&ts=%s" % (partial_url, sep, quote_plus(webid), quote_plus(ts))
