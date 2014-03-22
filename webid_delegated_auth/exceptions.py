"""
    Exceptions
"""


class AuthException(Exception):
    """
        Abstract Auth exception
    """
    pass


class UserAuthException(AuthException):
    """
        Exception due to the user (not the auth service)
    """
    pass


class NoClaimException(UserAuthException):
    """
        The user gave no assertion to prove
        its identity.

         Happens when the user wants to stay
         anonymous.

        New and generic

        Code: noClaim
    """


class NoCertException(NoClaimException):
    """
        The client did not provide a certificate.
        Specific to WebID-TLS.

        Code: nocert
    """
    pass


class RejectedClaimException(UserAuthException):
    """
        The user provided a claim
        but it has been rejected for some reasons
        (impossible to verify, wrong, expired, etc.)

        New! generic

        Code: rejectedClaim
    """



class ExpiredUserCertException(RejectedClaimException):
    """
        The client used a certificate that is expired
        Specific to WebID-TLS

        Code: certExpired

        TODO: get the expiration date
    """
    pass


class UndeclaredWebIdCertException(RejectedClaimException):
    """
        No entry for the user cert has been found
        in the WebID profile document.

        Specific to WebID-TLS

        Code: noVerifiedWebId
    """
    pass


class NotAWebIDException(RejectedClaimException):
    """
        The given URI is not a WebID (no profile
        document has been found)

        Code: noWebId
    """


class IdPException(RejectedClaimException):
    """
        Error with the Identity Provider

        Code: IdPError
    """
    pass


class AuthServiceError(AuthException):
    """
        Error while interacting with the Auth Service
    """
    pass


class InvalidServiceURLError(AuthServiceError):
    """ HTTPS is required """
    pass


class InvalidCallbackURLError(AuthServiceError):
    """ If HTTPS is required on the client-side (recommended) """
    pass


class RejectedAuthURLError(AuthServiceError):
    pass


class IncompleteAuthURLError(RejectedAuthURLError):
    """ WebID, ts and sig query entries are required
    """
    pass


class InvalidSignatureError(RejectedAuthURLError):
    """ The string $authreqissuer?webid=$webid&ts=$timeStamp has not
        signed by the expected certificate """
    pass


class ExpiredAuthURLError(RejectedAuthURLError):
    """ Too old timestamp
    """
    def __init__(self, expired_since):
        RejectedAuthURLError.__init__(self, "Auth URL has expired %d seconds ago"
                                            % expired_since)
        # In seconds
        self.expired_since = expired_since


class UnsyncClockError(RejectedAuthURLError):
    """
        When the negative time is too important
    """
    pass