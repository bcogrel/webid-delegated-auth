"""
    Exceptions.

    Compatibility with those declared in https://auth.my-profile.eu/
"""

NO_CLAIM_CODE = "noClaim"
NO_CERT_CODE = "nocert"
CERT_NO_OWNERSHIP_CODE = "certNoOwnership"
REJECTED_CLAIM_CODE = "rejectedClaim"
CERT_WITHOUT_URI_CODE = "noURI"
EXPIRED_CERT_CODE = "certExpired"
UNDECLARED_CERT_CODE = "noVerifiedWebId"
NOT_A_WEBID_CODE = "noWebId"
IDP_ERROR_CODE = "IdPError"


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


class CertNoOwnershipException(NoCertException):
    """
        The cert and its private key does not match.
        Strange mesage that may happen when the user
        refuses to show its cert.

        Specific to WebID-TLS

        Code: certNoOwnership
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
    pass


class CertWithoutUriException(RejectedClaimException):
    """
        The user cert does not contain an URI.
        The other claim is not considered.

        Specific to WebID-TLS

        Code: noURI
    """
    pass


class ExpiredUserCertException(RejectedClaimException):
    """
        The client used a certificate that is expired
        Specific to WebID-TLS

        Code: certExpired

        TODO: get the expiration date
    """
    pass


class UndeclaredCertException(RejectedClaimException):
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
