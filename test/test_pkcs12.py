from io import BytesIO
import logging
import pathlib
import re
import subprocess
import tempfile

import pytest

import nss.nss as nss
from setup_certs import CertificateDatabase
from util import resolve_path

# -------------------------------------------------------------------------------

logger = logging.getLogger()
pk12_passwd = "PK12_passwd"


def get_cert_der_from_db(db_name, nickname):
    cmd_args = [resolve_path("certutil"), "-d", db_name, "-L", "-n", nickname]

    try:
        process_result = subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode("utf-8")
        if e.returncode == 255 and "not found" in stderr:
            return None
        else:
            raise
    return process_result.stdout


def delete_cert_from_db(db_name, nickname):
    cmd_args = [resolve_path("certutil"), "-d", db_name, "-D", "-n", nickname]

    subprocess.check_call(cmd_args)


def pk12_tempfile(certdb):
    pk12_file = tempfile.NamedTemporaryFile()
    cmd_args = [
        resolve_path("pk12util"),
        "-o",
        pk12_file.name,
        "-n",
        certdb.client_nickname,
        "-d",
        certdb.db_name,
        "-K",
        certdb.db_passwd,
        "-W",
        pk12_passwd,
    ]
    subprocess.check_call(cmd_args)

    return pk12_file


def list_pk12(filename):
    cmd_args = [resolve_path("pk12util"), "-l", filename, "-W", pk12_passwd]
    return subprocess.check_output(cmd_args)


def strip_key_from_pk12_listing(text: str) -> str:
    match = re.search(r"^Certificate:$", text, re.MULTILINE)
    if not match:
        raise ValueError("Could not file Key section in pk12 listing")
    return text[match.start(0) :]


def strip_salt_from_pk12_listing(text: str) -> str:
    return re.sub(r"\s+Salt:\s*\n.*", "", text)


def setup_password_callback(password):
    def password_callback(slot, retry):
        return password

    nss.set_password_callback(password_callback)


def cert_der(certdb):
    der = get_cert_der_from_db(certdb.db_name, certdb.client_nickname)

    if der is None:
        raise ValueError('cert with nickname "%s" not in database "%s"' % (certdb.client_nickname, certdb.db_name))

    return der


class TestPKCS12Decoder:
    @classmethod
    def setup_class(cls):
        cls.basedir = tempfile.TemporaryDirectory()
        cls.certdb = CertificateDatabase(pathlib.Path(cls.basedir.name))
        nss.nss_init(cls.certdb.db_name)
        setup_password_callback(cls.certdb.db_passwd)

    @classmethod
    def teardown_class(cls):
        nss.nss_shutdown()
        cls.basedir.cleanup()
        del cls.basedir

    def test_read(self):
        logger.debug("test_read")
        pk12 = pk12_tempfile(self.certdb)
        pk12_filename = pk12.name

        slot = nss.get_internal_key_slot()
        pkcs12 = nss.PKCS12Decoder(pk12_filename, pk12_passwd, slot)

        assert len(pkcs12) == 3
        cert_bag_count = 0
        key_seen = None
        for bag in pkcs12:
            if bag.type == nss.SEC_OID_PKCS12_V1_CERT_BAG_ID:
                assert bag.shroud_algorithm_id is None
                cert_bag_count += 1
                if key_seen is None:
                    key_seen = bag.has_key
                elif key_seen is True:
                    assert not bag.has_key
                elif key_seen is False:
                    assert bag.has_key
                else:
                    pytest.fail("unexpected has_key for bag type = %s(%d)" % (nss.oid_tag_name(bag.type), bag.type))

            elif bag.type == nss.SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID:
                assert isinstance(bag.shroud_algorithm_id, nss.AlgorithmID)
                assert not bag.has_key
            else:
                pytest.fail("unexpected bag type = %s(%d)" % (nss.oid_tag_name(bag.type), bag.type))

        assert cert_bag_count == 2


class TestDestructive:
    # Destructive tests each get their own database
    def setup_method(self, method):
        self.basedir = tempfile.TemporaryDirectory()
        self.certdb = CertificateDatabase(pathlib.Path(self.basedir.name))
        nss.nss_init_read_write(self.certdb.db_name)
        setup_password_callback(self.certdb.db_passwd)

        self.pk12 = pk12_tempfile(self.certdb)
        self.pk12_filename = self.pk12.name

    def teardown_method(self, method):
        nss.nss_shutdown()
        del self.certdb

        self.basedir.cleanup()
        del self.basedir

        del self.pk12_filename
        del self.pk12

    def test_import_filename(self):
        logger.debug("test_import_filename")

        delete_cert_from_db(self.certdb.db_name, self.certdb.client_nickname)
        assert get_cert_der_from_db(self.certdb.db_name, self.certdb.client_nickname) is None

        slot = nss.get_internal_key_slot()
        pkcs12 = nss.PKCS12Decoder(self.pk12_filename, pk12_passwd, slot)
        slot.authenticate()
        pkcs12.database_import()
        db_cert_der = get_cert_der_from_db(self.certdb.db_name, self.certdb.client_nickname)
        assert db_cert_der == cert_der(self.certdb)

    def test_import_fileobj(self):
        logger.debug("test_import_fileobj")
        delete_cert_from_db(self.certdb.db_name, self.certdb.client_nickname)
        assert get_cert_der_from_db(self.certdb.db_name, self.certdb.client_nickname) is None

        slot = nss.get_internal_key_slot()

        with open(self.pk12_filename, "rb") as file_obj:
            pkcs12 = nss.PKCS12Decoder(file_obj, pk12_passwd, slot)
        slot.authenticate()
        pkcs12.database_import()
        db_cert_der = get_cert_der_from_db(self.certdb.db_name, self.certdb.client_nickname)
        assert db_cert_der == cert_der(self.certdb)

    def test_import_filelike(self):
        logger.debug("test_import_filelike")
        delete_cert_from_db(self.certdb.db_name, self.certdb.client_nickname)
        assert get_cert_der_from_db(self.certdb.db_name, self.certdb.client_nickname) is None

        slot = nss.get_internal_key_slot()

        with open(self.pk12_filename, "rb") as f:
            data = f.read()
        file_obj = BytesIO(data)

        pkcs12 = nss.PKCS12Decoder(file_obj, pk12_passwd, slot)
        slot.authenticate()
        pkcs12.database_import()
        db_cert_der = get_cert_der_from_db(self.certdb.db_name, self.certdb.client_nickname)
        assert db_cert_der == cert_der(self.certdb)


class TestPKCS12Export:
    @classmethod
    def setup_class(cls):
        cls.basedir = tempfile.TemporaryDirectory()
        cls.certdb = CertificateDatabase(pathlib.Path(cls.basedir.name))
        nss.nss_init(cls.certdb.db_name)
        setup_password_callback(cls.certdb.db_passwd)
        nss.pkcs12_enable_all_ciphers()

    @classmethod
    def teardown_class(cls):
        nss.nss_shutdown()
        cls.basedir.cleanup()
        del cls.basedir

    def test_export(self):
        logger.debug("test_export")
        pkcs12_data = nss.pkcs12_export(self.certdb.client_nickname, pk12_passwd)

        pk12 = pk12_tempfile(self.certdb)
        pk12_filename = pk12.name

        pk12_listing = list_pk12(pk12_filename)
        pk12_listing = strip_key_from_pk12_listing(pk12_listing.decode("utf-8"))
        pk12_listing = strip_salt_from_pk12_listing(pk12_listing)

        with tempfile.NamedTemporaryFile(delete=False) as export_temp:
            exported_pk12_filename = export_temp.name
            export_temp.write(pkcs12_data)
            export_temp.flush()
            exported_pk12_listing = list_pk12(exported_pk12_filename)

        exported_pk12_listing = strip_key_from_pk12_listing(exported_pk12_listing.decode("utf-8"))
        exported_pk12_listing = strip_salt_from_pk12_listing(exported_pk12_listing)

        assert pk12_listing == exported_pk12_listing
