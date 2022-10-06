import pathlib
import tempfile

import pytest

from nss.error import NSPRError
import nss.nss as nss
from setup_certs import CertificateDatabase

# -------------------------------------------------------------------------------

# At the moment the OCSP tests are weak, we just test we can
# successfully call each of the functions.


class TestAPI:
    @classmethod
    def setup_class(cls):
        cls.basedir = tempfile.TemporaryDirectory()
        certdb = CertificateDatabase(pathlib.Path(cls.basedir.name))
        cls.ca_nickname = certdb.ca_nickname
        nss.nss_init_read_write(certdb.db_name)

    @classmethod
    def teardown_class(cls):
        nss.nss_shutdown()
        cls.basedir.cleanup()
        del cls.basedir
        del cls.ca_nickname

    @property
    def certdb(self):
        return nss.get_default_certdb()

    def test_ocsp_cache(self):
        nss.set_ocsp_cache_settings(100, 10, 20)
        nss.clear_ocsp_cache()

    def test_ocsp_timeout(self):
        with pytest.raises(TypeError):
            nss.set_ocsp_timeout("ten")
        nss.set_ocsp_timeout(10)

    def test_ocsp_failure_mode(self):
        nss.set_ocsp_failure_mode(nss.ocspMode_FailureIsVerificationFailure)
        nss.set_ocsp_failure_mode(nss.ocspMode_FailureIsNotAVerificationFailure)
        with pytest.raises(NSPRError):
            nss.set_ocsp_failure_mode(-1)

    def test_ocsp_default_responder(self):
        # should raise error if cert is not known
        with pytest.raises(NSPRError):
            nss.set_ocsp_default_responder(self.certdb, "http://foo.com:80/ocsp", "invalid")
        nss.set_ocsp_default_responder(self.certdb, "http://foo.com:80/ocsp", self.ca_nickname)
        nss.enable_ocsp_default_responder()
        nss.disable_ocsp_default_responder()
        nss.enable_ocsp_default_responder(self.certdb)
        nss.disable_ocsp_default_responder(self.certdb)

    def test_enable_ocsp_checking(self):
        nss.enable_ocsp_checking()
        nss.disable_ocsp_checking()
        nss.enable_ocsp_checking(self.certdb)
        nss.disable_ocsp_checking(self.certdb)

    def test_use_pkix_for_validation(self):
        # Must be boolean
        with pytest.raises(TypeError):
            nss.set_use_pkix_for_validation("true")

        value = nss.get_use_pkix_for_validation()
        assert isinstance(value, bool)

        prev = nss.set_use_pkix_for_validation(not value)
        assert isinstance(prev, bool)
        assert value == prev
        assert nss.get_use_pkix_for_validation() == (not value)

        assert nss.set_use_pkix_for_validation(value) == (not value)
