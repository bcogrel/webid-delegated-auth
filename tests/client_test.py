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

final_cb = "https://localhost:5000/cb"

cb1_url = "https://localhost/login/cb?toto=raoul"
cb2_url = "https://localhost/login/cb"
cb3_url = "https://localhost/login/cb?final=%s" % quote_plus(final_cb)

response_1_url = "https://localhost/login/cb?toto=raoul&webid=https%3A%2F%2Fbenjamin.bcgl.fr%2Fprofile%23me&ts=2014-03-21CET22%3A13%3A55%2B01%3A00&sig=gt5hha9c9y72Pswo5uaiaT6wEfTJ43sa3Xi_VdkrsZvgb6-F1isJ-5EFKffljJ-x-BOhOfvf8ODG7cMVVpeD7rZBLpFXqi2z7bFEKnnwUWJlgGJLbd85NztR1HETLONRJVuibgCE0QvbN94BjPEkENCEHTQB2pA8gj1LB4_7Bs47-gc8Tdx1i5-7gLAyrtslLHrdjKAy6OTtCfP-t7mpjwZBM2uPoxr138Gjofp97Mjg3MQWL2qdlujlAs2gDlZd9kQqdI9k0SHXiBhSTqMEkq72F5alh0zn2nTRR60jdKHGxhaTvu-SrfibUrtPckxWtQl6573bC2n9gVzzmDwsgg&referer=https://auth.my-profile.eu"
response_2_url = "https://localhost/login/cb?webid=https%3A%2F%2Fbenjamin.bcgl.fr%2Fprofile%23me&ts=2014-03-21CET23%3A01%3A32%2B01%3A00&sig=UI5ekpDIrii45yDV3qZzltohCpJUPim1g8ZMaXkGAS1LOxGu0WAOPiiLd4Abr_nZmHYjUnU7o_JtZxH301z4PyGkQdBxPN_GSg7V9RtoIhd2mpmBIeJURWlCQR_kkmzGuAdO2Pn509PrRCXmsa8auWZ6DyiaMw-yJuxRfbIoptm5pmK_FWV5CPRorx6dwmP2vzvHZzAgC2E19XyBvA-8_a_dMbDpiQnTZN-x8Is51x4YUUysjQncH8LiQfYY-eFGM5vUbdZ9RMD2b0Ofjzno0AfP7oD5wYOFX8S7BPC7UqX_zonadJw5bseCRGjlBaTO30xvWuj6005vnUx844hu4Q&referer=https://auth.my-profile.eu"
response_3_url = "https://localhost/login/cb?final=https%3A%2F%2Flocalhost%3A5000%2Fcb&webid=https%3A%2F%2Fbenjamin.bcgl.fr%2Fprofile%23me&ts=2014-03-22CET14%3A42%3A47%2B01%3A00&sig=BMYWUrc2A1OnMwOOsuxutji2smIPmpqxRegdeRXM-bz5TkiIvPjKtn2LTfY__uPQChZf6nqfwB_wDLQaXwGMyimzQ7rKjGlcpW_fuuX13uFSlEG8sG2NCg-seI3rJ_NjiuahALENfUXDdm-aTuPwe9tOx6-452PZfAQSGvSyo-Lq4RUh5E01LKhx6Kzu9pEYe7oQMttWzTXI-7bBO5Jb9tZX7SW1Yi7vmGajccx4wyHTHnIf1hLoPl-HeDkdDk2nt8qX-MpEKTlhFRwp5UbF4Yx4ZXIntor_mVTVQLI9Jtoz2ECBzaLOKDYZfICo-zT3LzuEoRuRdSViPr2hdeFgKA&referer=https://auth.my-profile.eu"

# Modified signature
fake_resp_url = "https://localhost/login/cb?webid=https%3A%2F%2Fbenjamin.bcgl.fr%2Fprofile%23me&ts=2014-03-21CET23%3A01%3A32%2B01%3A00&sig=UI5ekpDIrii45yDV3qZzltohCpJUPim1g8ZMaXkGAS1LOxGu0WAOPiiLd4Abr_nZmHYjUnU7o_JtZxH301z4PyGkQdBxPN_GSg7V9RtoIhd2mpmBIeJURWlCQR_kkmzGuAdO2Pn509PrRCXmsa8auWZ6DyiaMw-yJuxRfbIoptm5pmK_FWV5CPRorx6dwmP2vzvHZzAgC2E19XyBvA-8_a_dMbDpiQnTZN-x8Is51x4YUUysjQncH8LiQfYY-eFGM5vUbdZ9RMD2b0Ofjzno0AfP7oD5wYOFX8S7BPC7UqX_zonadJw5bseCRGjlBaTO30xvWuj6005vnUx844hu99&referer=https://auth.my-profile.eu"
no_cert_resp_2_url = "https://localhost/login/cb?error=certNoOwnership&sig=Ef8KbcXF2QNg5kmJTXh1C83z00eq53apWhoN5mOMeHCxKhChIle5zZG8DUBgL0wn_A-I1wt7xSdYOFIwPwL_L-uobnm5aMXubYriXfoOp78-d8nrpxiAgKTvu34frupbgERGf8JxeCtgFocQPtbHYrpTI-ZoN2mtX7T1nmXDxQr9w17k_O7WJa_mLPdTQg6Ea0Dz-b8LJuP2rZOSCVaP7tNCwPKkkVWMbS_zdKySmmR354k_uRUpq9-GipsVmdtoMTgKQc54nExyJZK8Ts0dk-mkYmE9n4RCjRsDn9KW4FdRfKgCq7y7gTIf4UYEandq7npDujON6W8NquzMMfukkg&referer=https://auth.my-profile.eu"
#TODO: SIGNAL THIS BUG
no_cert_resp_3_url = "https://localhost/login/cb?final=https%3A%2F%2Flocalhost%3A5000%2Fcb?error=certNoOwnership&sig=ZrQXhG2QAj-GtsyixJQaQNNCivwnW05fJLRrNeKw6ytzQW6ZVMXBYoJZ2tyeRs4HNqgudXUaHh04pH2F4wEQ-geOTIvbcLr0wJONdchsnbMgNUtr6IXfL1QH7ueD5GzeZXCHmQZfRxWpQI-r-reg2fd1JCy5iLVWB6ItTStkJMB-CRyFcDgZfEUHCL8cNwm0W9hy6QeWEcpdk6gQh9ufPzuBIzBpdB0McJAm4vY6tlLbdQJY-o6vITwEYVuVx0FxRWH37ga4fxUbi6LeIHBGb3xledJKuT-4dDDaqnxt0RzR2FAezaw9Xsd4lfbZbCGMXzAD4G3fshgFVlgiDR15Tg&referer=https://auth.my-profile.eu"

no_uri_url = "https://localhost/login/cb?toto=raoul?error=noURI&sig=IfocoXWF4uYDZodcNLEuKVDf-9nGX3he_14sXK2Zc6I2UrsC9SoPGKK_SS_G5b7tOvxvsZicB_Im2Zv9i0mF1ie-mKKGXl_FRfRJuDOA5Cny5S7Keicc3QfLv7Uq9L_dRqCQR71g_kmZXP8FdlTfZ1h2bCjAMtO2gyMysEgJR0h6Fcl92j4DsnR92XOxrmPr8iY_xHzVV57ZruEPK1CbIdr9EkR3WC-ka2H78CfHihf9yxxweb1oNyQs61uzfbW9i2u651f2G5KHJKB3sCnEPmiNhPXW9s4tpvr2OwfWh15vjn92lKGcdbWFqM3kSngJGEDesR-maOcqLHiUdUzo_w&referer=https://auth.my-profile.eu"

webid = "https://benjamin.bcgl.fr/profile#me"


class ClientTest(TestCase):
    """
        Tests with https://auth.my-profile.eu

        More tests will be done with the server side
    """

    def setUp(self):
        self.mp_client = DelegatedAuthClient(mp_rsa_pubkey, mp_login_url)
        self.no_expiration_mp_client = DelegatedAuthClient(mp_rsa_pubkey, mp_login_url,
                                                           token_expiration=10e20)

    def test_no_https(self):
        self.assertRaises(InvalidServiceURLError, DelegatedAuthClient, mp_rsa_pubkey,
                          "http://example.com/login")

    def test_with_webid(self):
        self.assertEqual(self.mp_client.gen_request_url(cb1_url),
                         mp_login_url + "?authreqissuer=" + quote_plus(cb1_url))
        self.assertEqual(self.mp_client.gen_request_url(cb2_url),
                         mp_login_url + "?authreqissuer=" + quote_plus(cb2_url))
        self.assertEqual(self.mp_client.gen_request_url(cb3_url),
                         mp_login_url + "?authreqissuer=" + quote_plus(cb3_url))
        print self.mp_client.gen_request_url(cb3_url)

        # Too old
        self.assertRaises(ExpiredAuthURLError, self.mp_client.validate, response_1_url)


        # Bad signature
        self.assertRaises(InvalidSignatureError, self.no_expiration_mp_client.validate,
                          fake_resp_url)

        self.assertEquals(webid, self.no_expiration_mp_client.validate(response_1_url))
        self.assertEquals(webid, self.no_expiration_mp_client.validate(response_2_url))
        self.assertEquals(webid, self.no_expiration_mp_client.validate(response_3_url))

    def test_no_ownership(self):
        """ When there is no cert """
        self.assertRaises(CertNoOwnershipException, self.no_expiration_mp_client.validate, no_cert_resp_2_url)

    def test_cert_without_uri(self):
        self.assertRaises(CertWithoutUriException, self.no_expiration_mp_client.validate, no_uri_url)


