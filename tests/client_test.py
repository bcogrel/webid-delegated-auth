from unittest import TestCase
from webid_delegated_auth.client import DelegatedAuthClient
from webid_delegated_auth.exceptions import *
from urllib import quote_plus

mp_login_url = "https://auth.my-profile.eu/auth/index.php"

# Extract from the My-Profile X509 cert:
## openssl x509 -inform pem -in mp_cert.crt -noout -pubkey

mp_rsa_pubkey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSMeUiMcIGYxr8et1V2I
RVNvgPeBVxDu6q9UYtWXWVlIyLQVDbyuic3RQNaAD2LRjA7P1Hr/fSG4+BX1E90d
hmCNllr9ZxmZOs1xTedWd9iQF4dV4F9SFuO5oVX80dssv4t9cj59KDhIcgN0d3WD
7Nyuh03dRJ4Nq7c22InlSs2pk5FUJsjBtlhZiQWyeUKAkZBh0eWZ5Cf+I4WReNRs
k01u9XXMDm9yE4vRg7Eh7w+Y31E2cuT1zf/dR+PEna1VY+ihM4g+IexZzx6YM6bC
ibdcHoXPNxFkfPSBHmP3QutrDc9LNbDINQTYaKinrHQklIYxFERsqhlGhexnvtG2
iQIDAQAB
-----END PUBLIC KEY-----"""


# mp_rsa_pubkey = """-----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvnS5Etp0DLq/R3DeQrK0
# UnX04yTZhGYEtXFYrFncgwcTn7tJrbNYBQbQ1KPVcYE2KV6CjD2N802BhRyiAPyZ
# +NmDuCOckd0/50rZvf4lISHp2WGrQs9DZd8hwuIkRSfcVCdGTbLPOZmnZ5Cypr0R
# e/7PIlCRIi/cyel3dX3GHfUlJnH8mu4OQFLNRxM/Jko0+whmZTplaGfPktgp2egz
# PdB+84Ia61XmToTAxEhmknlSXVsP/YVuqLVlf4MH5GVfcwICiuGKA7hKtComhNjU
# nR7IbiI3fNWFJV/4BhKabWZUAu12rDHVEgin/nFIRH2h/qhmNLn0Odc6n2Lp4D3e
# YwIDAQAB
# -----END PUBLIC KEY-----"""



cb_url = "https://localhost/login/cb?toto=raoul"
#cb_url = "https://localhost/login/cb"

response_1_url = "https://localhost/login/cb?toto=raoul&webid=https%3A%2F%2Fbenjamin.bcgl.fr%2Fprofile%23me&ts=2014-03-21CET22%3A13%3A55%2B01%3A00&sig=gt5hha9c9y72Pswo5uaiaT6wEfTJ43sa3Xi_VdkrsZvgb6-F1isJ-5EFKffljJ-x-BOhOfvf8ODG7cMVVpeD7rZBLpFXqi2z7bFEKnnwUWJlgGJLbd85NztR1HETLONRJVuibgCE0QvbN94BjPEkENCEHTQB2pA8gj1LB4_7Bs47-gc8Tdx1i5-7gLAyrtslLHrdjKAy6OTtCfP-t7mpjwZBM2uPoxr138Gjofp97Mjg3MQWL2qdlujlAs2gDlZd9kQqdI9k0SHXiBhSTqMEkq72F5alh0zn2nTRR60jdKHGxhaTvu-SrfibUrtPckxWtQl6573bC2n9gVzzmDwsgg&referer=https://auth.my-profile.eu"
response_2_url = "https://localhost/login/cb?webid=https%3A%2F%2Fbenjamin.bcgl.fr%2Fprofile%23me&ts=2014-03-21CET23%3A01%3A32%2B01%3A00&sig=UI5ekpDIrii45yDV3qZzltohCpJUPim1g8ZMaXkGAS1LOxGu0WAOPiiLd4Abr_nZmHYjUnU7o_JtZxH301z4PyGkQdBxPN_GSg7V9RtoIhd2mpmBIeJURWlCQR_kkmzGuAdO2Pn509PrRCXmsa8auWZ6DyiaMw-yJuxRfbIoptm5pmK_FWV5CPRorx6dwmP2vzvHZzAgC2E19XyBvA-8_a_dMbDpiQnTZN-x8Is51x4YUUysjQncH8LiQfYY-eFGM5vUbdZ9RMD2b0Ofjzno0AfP7oD5wYOFX8S7BPC7UqX_zonadJw5bseCRGjlBaTO30xvWuj6005vnUx844hu4Q&referer=https://auth.my-profile.eu"

webid = "https://benjamin.bcgl.fr/profile#me"


class ClientTest(TestCase):

    def test(self):
        mp_client = DelegatedAuthClient(mp_rsa_pubkey, mp_login_url)

        self.assertEqual(mp_client.gen_request_url(cb_url), mp_login_url + "?authreqissuer="+quote_plus(cb_url))
        #print mp_client.gen_request_url(cb_url)

        # Too old
        self.assertRaises(ExpiredAuthURLError, mp_client.validate, response_1_url)

        no_expiration_mp_client = DelegatedAuthClient(mp_rsa_pubkey, mp_login_url,
                                                      token_expiration=10e20)
        self.assertEquals(webid, no_expiration_mp_client.validate(response_1_url))
        self.assertEquals(webid, no_expiration_mp_client.validate(response_2_url))

