"""RSA keypair used only by the DKIM verification tests.

Generated for this test suite and used nowhere else. It signs synthetic sample
messages so the DKIM tests verify a *real* signature end to end rather than asserting
against a mock. Publishing it is harmless: it protects nothing.
"""

TEST_SELECTOR = "testsel"
TEST_DOMAIN = "bank.example"

PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC0mo2TYxoh4VsT
MJvngc2xvgNNAqPjGt1++D6O4N4dSLuAUX8WbR/pdbnNGoNi9a9n6xbi4Q9lnUvs
r1Ef6stl6spKwllWPUlwSzlLVx15/qlRIRQFpfsT4XM30Lj0xZH9yxedjxvcBptL
LfvW4tmJJw7a5yFlRZAOBhRX0xH3vODv0nWzQnKVjKuOTE4tiUzpCn7K/XAZXWgn
z5eN3P7YQmDrLxMwBjM4+XZGb1XrWLPQhLcBLX9n/uiaJJtr5OSN0IykwmpSfwKh
saKnv/YodmYezAnQrtoTdRh86k0fx7mJ9IByiH798gCbAh1CDoQZyGN4jNaB8i+r
fERvrYktAgMBAAECggEAC9dbTiJ6sZB7PnJFh+OxQcSzJjQ0scdOkPcum4MVBRIC
UIA8vH1vUMkEzjS9Zbpf47Nx/Bz5+7VZEkhktwVCYekHlj27tPAOldkqGpgNs8ng
Pj8UjJHso58jRQb/bXWxDqpndA+QlHfuwXqJxHXPV1L9126SjbeGdv5BN13nKRk3
CQYYPTjEJu1lBIyC0j+HLsIICkSwsooSS57W1YCO7GpNKNdt8nT4G9KswcHrKlkv
RmQVtaG1qSUrPwg/EKm64+Qt1w+ybeqB5pL0cHnQfzKbyn+95u75ED/p2UqAuAp7
5FeKvjhI0JyxIhvQzJWiuoCqtiddHVUKuCa0TYKVOQKBgQD9gd7pBY49ktjQ8KnM
gNZBxe0p0Q/HYd2+zGhdemtEMRQdAjGbeJjaYHPE2E+/fjhA8VUlCu4GLQK38N0a
4CyUGK02BZ0+A0nMy2IUMxvm4gQYd49aTE81A9Obv7N7tDG12fjQzDrx4aBMlOv2
jApnFOldAJGK46KHwVSLs75sWQKBgQC2YStQOmat5t8/5WY2OVdfYfne10KkwY+r
APx3bO5nlqtWyuxFsWekwAdkzCvLsU6u+yp12muLJu1zev4vo8vsDVmHv7obk4W1
539hr+ub6ZBOaVQ5g2DPyi35rlftflxXofn2l0hkBewrGfvIn8H+TGzXisnsoAjY
SP9Q25OY9QKBgDn23Qo46/omPo8fyCNrfhIR+JVsKQh01ygOQvrEyAwSkL/FRaR/
4atlDHOA5lMpwCERTV+n7R7aYdm/KD9B7M98CPbmN7r7M3+xLV7jBMk4+qjBhbSm
6CF+G39sSNTLMeabzWmomP2/klCQaJe6E5LYVDegrqasP/h8eyFqWusZAoGAIsQh
KpkHa80f76E+O8Xwhuk5ZaZpONkBFxsIBYgJZkvNe60RHzPzSu+kOS3Gh3zUP/z3
GiI57/vKtgHTJKe3vtbIo10EEC+uBIANw0RyyHTcomXnvVLzCIlE/FykvEwjND1X
Vg9+qDqMy6aXXaY+p8hP00LMvUPAi+JWcUZ6O2UCgYAi8E9Z4SnQrAmUX9uvHpAg
tDgx2w2B2nIofTpW+UoYbgHdDuEiKTpcTttCj2Twz+bXsSG48RMpuGMUOXKYEttF
RoDd+QXXP6MGfnaa1+mNUTwV8cyd0gMY8L7mTlXZkzUTKmYP9zqs855mm0zCJFeP
mGWEcMJE84blM68jATt38Q==
-----END PRIVATE KEY-----
"""

# The DNS TXT record that testsel._domainkey.bank.example would publish.
PUBLIC_KEY_RECORD = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJqNk2MaIeFbEzCb54HNsb4DTQKj4xrdfvg+juDeHUi7gFF/Fm0f6XW5zRqDYvWvZ+sW4uEPZZ1L7K9RH+rLZerKSsJZVj1JcEs5S1cdef6pUSEUBaX7E+FzN9C49MWR/csXnY8b3AabSy371uLZiScO2uchZUWQDgYUV9MR97zg79J1s0JylYyrjkxOLYlM6Qp+yv1wGV1oJ8+Xjdz+2EJg6y8TMAYzOPl2Rm9V61iz0IS3AS1/Z/7omiSba+TkjdCMpMJqUn8CobGip7/2KHZmHswJ0K7aE3UYfOpNH8e5ifSAcoh+/fIAmwIdQg6EGchjeIzWgfIvq3xEb62JLQIDAQAB"
