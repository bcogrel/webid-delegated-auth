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

response_1_url = "https://localhost/login/cb?toto=raoul&webid=https%3A%2F%2Fmy-profile.eu%2Fpeople%2Fbcogrel-testonly%2Fcard%23me&ts=2014-03-23CET14%3A00%3A18%2B01%3A00&sig=KTjwlsMqkRTW5ZLpid_aTK7DL6-OrXYa5cHBQ9H9MpXWdh2UZRV-8stQ2GYykZ0Yq7oVALjfIfacSVWfBN3cPP88yzkNgOhh8LxR0khgL6l4VWzO2W-d-08x0fNtdBOI4oRUvWZjXYxeOQ6RZdNX3cM5iTPBzCuuMqFq3hAkyX_2dmByod4ZVXa1J35Ay-_8p-u8TaAwaJClZiXemeCdi_zm6sUEPMcF12pMpMI3gVar4mQ8iWNOWxE1jL9d3b2sw_vRyUL1UoCR2uichochEPWts49LV-G1jPVMTzEaroGwq5I5Hr05KeOyW-XP5RdfVPdSPTfQ3a1lcpAX3Zr6Gw&referer=https://auth.my-profile.eu"
response_2_url = "https://localhost/login/cb?webid=https%3A%2F%2Fmy-profile.eu%2Fpeople%2Fbcogrel-testonly%2Fcard%23me&ts=2014-03-23CET14%3A01%3A02%2B01%3A00&sig=lvy8uD1fwgPNhQCeIZdJY2EAj9WXAOkn9l9BxZ5-2w6pqnvbWTgoe5M0S5GzsugSVyzRp1F4NEcdYR1TkzDKh0qrg1vCrCF6gW_xG3Dhr0Pm5kPYQLIytfVse0KC2Q1aQxIHbLsMe4F0xZr0-r8c5t4oS2_92HT3UzdCa22xrNsy90MlmnkYg29adNyeTWp1VSQHiu-nlLYLlwtM_9pSSkGfhv6S_tuRgPL6-edSMHL6lfqiToHLFqrz1iaWBZi1ih1Rg3zl0N5C-XJPpfkLA0pOLDuc-X4IA46JR4QdCx4QGrSGj1DNEQzLTPp74vKCzFrZtKos1VJKXQ2evr43tw&referer=https://auth.my-profile.eu"
response_3_url = "https://localhost/login/cb?final=https%3A%2F%2Flocalhost%3A5000%2Fcb&webid=https%3A%2F%2Fmy-profile.eu%2Fpeople%2Fbcogrel-testonly%2Fcard%23me&ts=2014-03-23CET14%3A01%3A26%2B01%3A00&sig=VYubqpkHOfJXBU0YzRQAVAt8UIZEZR9zmQ_S1JpooAjhN2-CbrC7x1iXQ0hXpWvKdx5NfURao2Rd0iIhQzoNFq6ul4hg9pqJWOmwI_u9mkxnzEnGeXi-IhUsD4ty-o1tjo_xxl5QeapxxkE6EnPT3A2IucdmbkymIy-MrK59FCRxe1rd3XoDpn3_3b8ZPZKrTp4ypbOh6ViguTgUNPt26quAKYmKkMmUxf4tDN6XDnvYyoL5yO0r7DWcS2VDSJ6iB-HpReiPkeHiJ_26gZ8PXgwdZDhRZQDF5AcIcUPmMsChnPQUWy_rqwmMHG2SEubk_QkBysB7Gl_nMyFGLst9Gg&referer=https://auth.my-profile.eu"

# Modified signature
fake_resp_url = "https://localhost/login/cb?final=https%3A%2F%2Flocalhost%3A5000%2Fcb&webid=https%3A%2F%2Fmy-pro.eu%2Fpeople%2Fbcogrel-testonly%2Fcard%23me&ts=2014-03-23CET14%3A01%3A26%2B01%3A00&sig=VYubqpkHOfJXBU0YzRQAVAt8UIZEZR9zmQ_S1JpooAjhN2-CbrC7x1iXQ0hXpWvKdx5NfURao2Rd0iIhQzoNFq6ul4hg9pqJWOmwI_u9mkxnzEnGeXi-IhUsD4ty-o1tjo_xxl5QeapxxkE6EnPT3A2IucdmbkymIy-MrK59FCRxe1rd3XoDpn3_3b8ZPZKrTp4ypbOh6ViguTgUNPt26quAKYmKkMmUxf4tDN6XDnvYyoL5yO0r7DWcS2VDSJ6iB-HpReiPkeHiJ_26gZ8PXgwdZDhRZQDF5AcIcUPmMsChnPQUWy_rqwmMHG2SEubk_QkBysB7Gl_nMyFGLst9Gg&referer=https://auth.my-profile.eu"
no_cert_resp_2_url = "https://localhost/login/cb?error=certNoOwnership&sig=Ef8KbcXF2QNg5kmJTXh1C83z00eq53apWhoN5mOMeHCxKhChIle5zZG8DUBgL0wn_A-I1wt7xSdYOFIwPwL_L-uobnm5aMXubYriXfoOp78-d8nrpxiAgKTvu34frupbgERGf8JxeCtgFocQPtbHYrpTI-ZoN2mtX7T1nmXDxQr9w17k_O7WJa_mLPdTQg6Ea0Dz-b8LJuP2rZOSCVaP7tNCwPKkkVWMbS_zdKySmmR354k_uRUpq9-GipsVmdtoMTgKQc54nExyJZK8Ts0dk-mkYmE9n4RCjRsDn9KW4FdRfKgCq7y7gTIf4UYEandq7npDujON6W8NquzMMfukkg&referer=https://auth.my-profile.eu"
no_cert_resp_3_url = "https://localhost/login/cb?final=https%3A%2F%2Flocalhost%3A5000%2Fcb?error=certNoOwnership&sig=ZrQXhG2QAj-GtsyixJQaQNNCivwnW05fJLRrNeKw6ytzQW6ZVMXBYoJZ2tyeRs4HNqgudXUaHh04pH2F4wEQ-geOTIvbcLr0wJONdchsnbMgNUtr6IXfL1QH7ueD5GzeZXCHmQZfRxWpQI-r-reg2fd1JCy5iLVWB6ItTStkJMB-CRyFcDgZfEUHCL8cNwm0W9hy6QeWEcpdk6gQh9ufPzuBIzBpdB0McJAm4vY6tlLbdQJY-o6vITwEYVuVx0FxRWH37ga4fxUbi6LeIHBGb3xledJKuT-4dDDaqnxt0RzR2FAezaw9Xsd4lfbZbCGMXzAD4G3fshgFVlgiDR15Tg&referer=https://auth.my-profile.eu"

no_uri_url = "https://localhost/login/cb?toto=raoul?error=noURI&sig=IfocoXWF4uYDZodcNLEuKVDf-9nGX3he_14sXK2Zc6I2UrsC9SoPGKK_SS_G5b7tOvxvsZicB_Im2Zv9i0mF1ie-mKKGXl_FRfRJuDOA5Cny5S7Keicc3QfLv7Uq9L_dRqCQR71g_kmZXP8FdlTfZ1h2bCjAMtO2gyMysEgJR0h6Fcl92j4DsnR92XOxrmPr8iY_xHzVV57ZruEPK1CbIdr9EkR3WC-ka2H78CfHihf9yxxweb1oNyQs61uzfbW9i2u651f2G5KHJKB3sCnEPmiNhPXW9s4tpvr2OwfWh15vjn92lKGcdbWFqM3kSngJGEDesR-maOcqLHiUdUzo_w&referer=https://auth.my-profile.eu"

webid = "https://my-profile.eu/people/bcogrel-testonly/card#me"


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
        self.assertRaises(ExpiredAuthURLError, self.mp_client.check, response_1_url)


        # Bad signature
        self.assertRaises(InvalidSignatureError, self.no_expiration_mp_client.check,
                          fake_resp_url)

        self.assertEquals(webid, self.no_expiration_mp_client.check(response_1_url))
        self.assertEquals(webid, self.no_expiration_mp_client.check(response_2_url))
        self.assertEquals(webid, self.no_expiration_mp_client.check(response_3_url))

    def test_no_ownership(self):
        """ When there is no cert """
        self.assertRaises(CertNoOwnershipException, self.no_expiration_mp_client.check, no_cert_resp_2_url)

    def test_cert_without_uri(self):
        self.assertRaises(CertWithoutUriException, self.no_expiration_mp_client.check, no_uri_url)


