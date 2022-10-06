import hashlib
import os

from conftest import digest_test
import nss.nss as nss


class TestDigest:

    reference_file = os.path.abspath(__file__)

    @classmethod
    def setup_class(cls):
        nss.nss_init_nodb()

    @classmethod
    def teardown_class(cls):
        nss.nss_shutdown()

    def test_md5(self):
        digest_test("md5", self.reference_file, hashlib.md5(), nss.md5_digest, nss.SEC_OID_MD5)

    def test_sha1(self):
        digest_test("sha1", self.reference_file, hashlib.sha1(), nss.sha1_digest, nss.SEC_OID_SHA1)

    def test_sha256(self):
        digest_test("sha256", self.reference_file, hashlib.sha256(), nss.sha256_digest, nss.SEC_OID_SHA256)

    def test_sha512(self):
        digest_test("sha512", self.reference_file, hashlib.sha512(), nss.sha512_digest, nss.SEC_OID_SHA512)
