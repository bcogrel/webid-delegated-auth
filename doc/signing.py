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