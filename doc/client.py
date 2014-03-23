# Public RSA key of https://auth.my-profile.eu
pubkey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSMeUiMcIGYxr8et1V2I
RVNvgPeBVxDu6q9UYtWXWVlIyLQVDbyuic3RQNaAD2LRjA7P1Hr/fSG4+BX1E90d
hmCNllr9ZxmZOs1xTedWd9iQF4dV4F9SFuO5oVX80dssv4t9cj59KDhIcgN0d3WD
7Nyuh03dRJ4Nq7c22InlSs2pk5FUJsjBtlhZiQWyeUKAkZBh0eWZ5Cf+I4WReNRs
k01u9XXMDm9yE4vRg7Eh7w+Y31E2cuT1zf/dR+PEna1VY+ihM4g+IexZzx6YM6bC
ibdcHoXPNxFkfPSBHmP3QutrDc9LNbDINQTYaKinrHQklIYxFERsqhlGhexnvtG2
iQIDAQAB
-----END PUBLIC KEY-----"""

from webid_delegated_auth import *

mp_client = DelegatedAuthClient(pubkey, "https://auth.my-profile.eu/auth/index.php",
                                # 5 min. Default is 60s
                                token_expiration=300)

# Callback URL where you will receive the auth URL
cb_url = "https://localhost/login/cb"

# URL to which you should redirect your user
request_url = mp_client.gen_request_url(cb_url)
print "Request: %s" % request_url


# Redirected URL from auth.my-profile.eu
# Change it
auth_url = "https://localhost/login/cb?webid=https%3A%2F%2Fmy-profile.eu%2Fpeople%2Fbcogrel-testonly%2Fcard%23me&ts=2014-03-23CET13%3A55%3A53%2B01%3A00&sig=gEBEawmo69Tb6vklQIPic1IzUePNZ0rSENCXYtVry55khAKD27DDWI7XNXtle6pLhjo4_BUaPTKLCre640Y5wnat1zTva71N70d7XttfzCQCbzKjp_kdruuY97WslmmFV6hm_0KliuaEHg1m1NAMjawntWwOEC3oAuKhXhIQPgiV4nQNG7x2h53yrP4oJL-q-ltgSI9Fn83mY3Vn6ENu0IN1KC3_aDJ2uERyJEiamX-WbB8OSLxdjN4cmg-Kv1WdSpBTQOmF2MHjvBd7mGwWtJ_Ogr36O1TtyAaEE_z2TUlOeQNE0sW7WRYNma47kUz630nBh3X0nwPTGJkAXpSbMg&referer=https://auth.my-profile.eu"

try:
    webid = mp_client.check(auth_url)

    print "Your webID: %s" % webid

except ExpiredAuthURLError as e:
    # Expired authentication URL (if you used mine)
    print "Error: %s " % e
except UserAuthException as e:
    print "Impossible to authenticate the user. Reason: %s" % e.__class__.__name__

except AuthServiceError as e:
    # Problem with auth.my-profile.eu
    print "Problem with the auth service: %s " % e.__class__.__name__
