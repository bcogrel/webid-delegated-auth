webid-delegated-auth
====================

WebID delegated authentication Python tools (signing and checking auth URLs).

Compatible with auth services running `the WebIDDelegatedAuth PHP library
<https://github.com/WebIDauth/WebIDDelegatedAuth>`_.


Requirements
------------
* Python 2.7
* M2Crypto (uses OpenSSL)
* python-dateutil


Examples
--------

Go to `doc/examples <https://github.com/bcogrel/webid-delegated-auth/tree/master/doc/examples>`_
for a better reading experience (with syntax highlight).

Logging WebID-TLS users
~~~~~~~~~~~~~~~~~~~~~~~

Into your website, by using https://auth.my-profile.eu

::

    from webid_delegated_auth import *

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

    mp_client = DelegatedAuthClient(pubkey, "https://auth.my-profile.eu/auth/index.php",
                                            # 5 min. Default is 60s
                                            token_expiration=300)

    # Callback URL where you will receive the auth URL
    # Replace it
    cb_url = "https://localhost/login/cb"

    # URL to which you should redirect your user
    request_url = mp_client.gen_request_url(cb_url)
    print request_url

Will display::

    https://auth.my-profile.eu/auth/index.php?authreqissuer=https%3A%2F%2Flocalhost%2Flogin%2Fcb

Click on `this link <https://auth.my-profile.eu/auth/index.php?authreqissuer=https%3A%2F%2Flocalhost%2Flogin%2Fcb>`_
and authenticate yourself with your WebID-TLS cert.
If you don't have a cert, you create one quickly on https://my-profile.eu/profile .

You will then be redirect to an URL. Copy it and run the following instructions::

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

If you have not changed the auth url, you will see that the following message::

    Error: Auth URL has expired XXXX seconds ago


If you take a very long token expiration duration, you will able to see the WebID I used.


Signing Auth URLs
~~~~~~~~~~~~~~~~~

If you can use the URLSigningService to build a WebID authentication service
(with or without WebID-TLS)::

    from webid_delegated_auth import *

    private_key = """-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAo1fwKZKfuZM/aJQN6qYueh18Sz6wuWxf9P4y9A4Kyv3dFcAj
    ztLEKaXQnL6lzsEkM4cei9VTnL+vOPYcy9fucmMJM9VEWPVH2RIyRI5u8f3C0Dyw
    tU34E0HfjUd4Ak13/EZXmfEsKdTf+huxMY7l3uX75QKbV1jqQHlPwxMpqSgPWr52
    x+Uu8ryaggO+d5mnknvtgPIVSH562kPTqopMXncpja4VrXtWIp/w1r3cwq7ZgKvS
    hKhDGl1p8hEqgD5vvKIP2ds9YaNYgLDaYzMjkbHtvBc57LrfXU4wiU22steeLBHG
    4wOJbn+NSGBModxA6l0c4eYuXIXlqzlZd5sZlwIDAQABAoIBADwKAbu2KkGS7xao
    fOkIBkNafSpHM7wkKq0pll8AnlT4tP/erQrDi9jnGuPSa62wbncGLmMlmWMfTe+4
    /uKqTvn6jxJfTI0KM0uFlbZ/SCZoqOfTtvwdWZbyepI6d9EY2oZ+8IokDKCfn2gW
    L65QoQuqK0mFCMY1Z30lWf0RGRoUihcpCUKH1YE6EghgE1ASGxKgyd94oy5l5UV1
    +e5fSvmukjVZkcXPjFwZn2FMT5io+FfBa4FgoUEi9RJ5pMH1RsRy9hejPZP4RrQE
    C7l2KjCEOxvA0ZNMGSgAcL4IPUnFueR2nEtz1gStYi2MZ0GDs7iQuTIAyBcMRhTq
    4afnsHkCgYEA0eh8YXbYYt2lVawflMjil7WH+RqhsPCBQp+f/UjRlS5q/Sez7/wg
    n1aNazAwkjHzFogbvSBb16YiIMl8rBsL7XQ6Ai7Dsfeyt9eoCh8zI7huDFS1mZSe
    CWFpMTnhly2mcMhaEZMgjKWEBhlUMPFWMJbBUkPA63KTAK/DuBUOIEMCgYEAxzXt
    BKsVRwHZdT+hnkXG8AQa8NY2sDYZFnvV6K2bwKrfICrOkv12npIcidllYFy3tmxO
    iuDWgOxvKnOnbdTmaPi8no3SKuUUXCH0OzaD4ytK4JB/vZFi6vYLDmVbcg/jZmRh
    vH7TbJQQrYcTyzMXMp4vmRDVzOZlO1OiXXUyph0CgYAjJTb2JqzyWMQfBRPAmKX/
    2sAqgEAEXTB3VDy4buHQhZYaTvR8wQ1BQH+rK8VmJQDbi+yBDRLzl3htXu8F7f1g
    Q66WwPe5K4z75RrYnwKz/2RFokVJsq2HSo0PVe6knlsY1SLngGfZxLjHQKRtEWtp
    9UPnHzsE8QkV+1fc0YGs+wKBgQCC6ALawHn48VQu4iOYWA4Ehw4VGQ9S+BnAVpwY
    jIz/LMn232pj2T9rsGQkicE+c28d50otpNYQXk4mvV1WpULL1DhOkK99FJAugvl1
    N7uvOjG4I/xtW+5+rDRTv3M6Hwq1rF01eroAbcQP4+Wz79zcnGp20UNNpFD9jVXy
    yCMCWQKBgEuVABKo/679QwiXG+L0x5cIQtIoHTpsNAfdNYBkAXkNsxjbGkBOrKVE
    qaMI6vGqovsL9NpdteFEKxMGd831vF9/uZJzoMOPW69YgX0NXm7k9FltBkUqI8T5
    tyNleVwT49UmLF7cMTZS0nPro9u+ktHqwP30H44MZmpj0Q5rPkiC
    -----END RSA PRIVATE KEY-----"""

    # Your auth service root URL
    # Change it
    referer_url = "https://example.org"
    signing_service = URLSigningService(private_key, referer_url)


    # Tested WebID
    webid = "https://my-profile.eu/people/bcogrel-testonly/card#me"
    requester_url = "https://localhost/login/cb"

    auth_url = signing_service.gen_auth_url(webid, requester_url)
    print "Auth URL: %s" % auth_url

    # Error: no claim provided by the user
    error_url = signing_service.gen_no_claim_error_url(requester_url)
    print "No claim error URL: %s" % error_url


Have fun!
