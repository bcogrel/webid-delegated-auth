"""
    Exceptions
"""


class AuthClientError(Exception):
    pass


class InvalidServiceURLError(AuthClientError):
    """ HTTPS is required """
    pass


class InvalidCallbackURLError(AuthClientError):
    """ If HTTPS is required on the client-side (recommended) """
    pass


class RejectedAuthURLError(AuthClientError):
    pass


class IncompleteAuthURLError(RejectedAuthURLError):
    """ webid, ts and sig query entries are required
    """
    pass


class InvalidSignatureError(RejectedAuthURLError):
    """ The string $authreqissuer?webid=$webid&ts=$timeStamp has not
        signed by the expected certificate """
    pass


class ExpiredAuthURLError(RejectedAuthURLError):
    """ Too old timestamp
    """
    pass