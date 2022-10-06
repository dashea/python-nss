from collections.abc import Generator
from contextlib import contextmanager
import logging
import os
import pathlib
import re
import subprocess
from tempfile import NamedTemporaryFile
import typing

import pytest

from util import resolve_path

logger = logging.getLogger()

FIPS_SWITCH_FAILED_ERR = 11
FIPS_ALREADY_ON_ERR = 12
FIPS_ALREADY_OFF_ERR = 13

_StrOrPath: typing.TypeAlias = str | os.PathLike[str]


@contextmanager
def _passwd_file(db_passwd: str) -> Generator[str, None, None]:
    with NamedTemporaryFile() as f:
        f.write(db_passwd.encode("utf-8"))
        yield f.name


@contextmanager
def _noise_file() -> Generator[str, None, None]:
    random_data = os.urandom(40)

    with NamedTemporaryFile() as f:
        f.write(random_data)
        yield f.name


def _create_database(db_passwd: str, db_name: str):
    with _passwd_file(db_passwd) as pw:
        cmd_args = [resolve_path("certutil"), "-N", "-d", db_name, "-f", pw]
        subprocess.check_call(cmd_args)


def _increment_serial(serial_file: _StrOrPath) -> int:
    fd = os.open(serial_file, os.O_RDWR | os.O_CREAT, mode=0o644)
    try:
        os.lockf(fd, os.F_LOCK, 0)
        try:
            with os.fdopen(fd, "r+", closefd=False) as sf:
                serial_data = sf.readline()
                if serial_data == "":
                    serial_number = 1
                else:
                    serial_number = int(serial_data, 16)
                sf.seek(0)
                sf.write("%x\n" % (serial_number + 1,))

            return serial_number
        finally:
            os.lockf(fd, os.F_ULOCK, 0)
    finally:
        os.close(fd)


def _create_ca_cert(
    db_name: str,
    passwd_file: _StrOrPath,
    serial_file: _StrOrPath,
    ca_subject: str,
    ca_nickname: str,
    key_size: int,
    valid_months: int,
    ca_path_len: int,
) -> str:
    serial_number = _increment_serial(serial_file)

    logging.info('creating ca cert: subject="%s", nickname="%s"', ca_subject, ca_nickname)

    # Provide input for extension creation prompting
    input_data = ""

    # >> Key Usage extension <<
    # 0 - Digital Signature
    # 1 - Non-repudiation
    # 2 - Key encipherment
    # 3 - Data encipherment
    # 4 - Key agreement
    # 5 - Cert signing key
    # 6 - CRL signing key
    # Other to finish
    input_data += "0\n1\n5\n100\n"
    # Is this a critical extension [y/N]?
    input_data += "y\n"

    # >> Basic Constraints extension <<
    # Is this a CA certificate [y/N]?
    input_data += "y\n"
    # Enter the path length constraint, enter to skip [<0 for unlimited path]: > 2
    input_data += "%d\n" % ca_path_len
    # Is this a critical extension [y/N]?
    input_data += "y\n"

    # >> NS Cert Type extension <<
    # 0 - SSL Client
    # 1 - SSL Server
    # 2 - S/MIME
    # 3 - Object Signing
    # 4 - Reserved for future use
    # 5 - SSL CA
    # 6 - S/MIME CA
    # 7 - Object Signing CA
    # Other to finish
    input_data += "5\n6\n7\n100\n"
    # Is this a critical extension [y/N]?
    input_data += "n\n"

    with _noise_file() as nf:
        cmd_args = [
            resolve_path("certutil"),
            "-S",  # OPERATION: create signed cert
            "-x",  # self-sign the cert
            "-d",
            db_name,  # NSS database
            "-f",
            passwd_file,  # database password in file
            "-n",
            ca_nickname,  # nickname of cert being created
            "-s",
            ca_subject,  # subject of cert being created
            "-g",
            str(key_size),  # keysize
            "-t",
            "CT,,CT",  # trust
            "-1",  # add key usage extension
            "-2",  # add basic contraints extension
            "-5",  # add certificate type extension
            "-m",
            str(serial_number),  # cert serial number
            "-v",
            str(valid_months),  # validity in months
            "-z",
            nf,  # noise file random seed
        ]

        subprocess.run(cmd_args, input=input_data.encode("utf-8"), check=True)

    return ca_nickname


def _create_server_cert(
    db_name: str,
    passwd_file: _StrOrPath,
    serial_file: _StrOrPath,
    ca_nickname: str,
    server_subject: str,
    server_nickname: str,
    key_size: int,
    valid_months: int,
) -> str:
    serial_number = _increment_serial(serial_file)

    logging.info('creating server cert: subject="%s", nickname="%s"', server_subject, server_nickname)

    # Provide input for extension creation prompting
    input_data = ""

    # >> NS Cert Type extension <<
    # 0 - SSL Client
    # 1 - SSL Server
    # 2 - S/MIME
    # 3 - Object Signing
    # 4 - Reserved for future use
    # 5 - SSL CA
    # 6 - S/MIME CA
    # 7 - Object Signing CA
    # Other to finish
    input_data += "1\n100\n"
    # Is this a critical extension [y/N]?
    input_data += "n\n"

    with _noise_file() as nf:
        cmd_args = [
            resolve_path("certutil"),
            "-S",  # OPERATION: create signed cert
            "-d",
            db_name,  # NSS database
            "-f",
            passwd_file,  # database password in file
            "-c",
            ca_nickname,  # nickname of CA used to sign this cert
            "-n",
            server_nickname,  # nickname of cert being created
            "-s",
            server_subject,  # subject of cert being created
            "-g",
            str(key_size),  # keysize
            "-t",
            "u,u,u",  # trust
            "-5",  # add certificate type extensionn
            "-m",
            str(serial_number),  # cert serial number
            "-v",
            str(valid_months),  # validity in months
            "-z",
            nf,  # noise file random seed
        ]

        subprocess.run(cmd_args, input=input_data.encode("utf-8"), check=True)

    return server_nickname


def _create_client_cert(
    db_name: str,
    passwd_file: _StrOrPath,
    serial_file: _StrOrPath,
    ca_nickname: str,
    client_subject: str,
    client_nickname: str,
    key_size: int,
    valid_months: int,
) -> str:
    serial_number = _increment_serial(serial_file)

    logging.info('creating client cert: subject="%s", nickname="%s"', client_subject, client_nickname)

    # Provide input for extension creation prompting
    input_data = ""

    # >> NS Cert Type extension <<
    # 0 - SSL Client
    # 1 - SSL Server
    # 2 - S/MIME
    # 3 - Object Signing
    # 4 - Reserved for future use
    # 5 - SSL CA
    # 6 - S/MIME CA
    # 7 - Object Signing CA
    # Other to finish
    input_data += "0\n100\n"
    # Is this a critical extension [y/N]?
    input_data += "n\n"

    with _noise_file() as nf:
        cmd_args = [
            resolve_path("certutil"),
            "-S",  # OPERATION: create signed cert
            "-d",
            db_name,  # NSS database
            "-f",
            passwd_file,  # database password in file
            "-c",
            ca_nickname,  # nickname of CA used to sign this cert
            "-n",
            client_nickname,  # nickname of cert being created
            "-s",
            client_subject,  # subject of cert being created
            "-g",
            str(key_size),  # keysize
            "-t",
            "u,u,u",  # trust
            "-5",  # add certificate type extensionn
            "-m",
            str(serial_number),  # cert serial number
            "-v",
            str(valid_months),  # validity in months
            "-z",
            nf,  # noise file random seed
        ]
        print("RUNNING %s" % str(cmd_args))
        result = subprocess.run(cmd_args, input=input_data.encode("utf-8"), check=True)
        print("RESULT %s" % result)

    return client_nickname


def _add_trusted_certs(db_name: str):
    name = "ca_certs"
    module = "libnssckbi.so"
    logging.info('adding system trusted certs: name="%s" module="%s"', name, module)

    cmd_args = [
        resolve_path("modutil"),
        "-dbdir",
        db_name,  # NSS database
        "-add",
        name,  # module name
        "-libfile",
        module,  # module
    ]

    subprocess.check_call(cmd_args)


def _parse_fips_enabled(string: str):
    if re.search("FIPS mode disabled", string):
        return False
    if re.search("FIPS mode enabled", string):
        return True
    raise ValueError('unknown fips enabled string: "%s"' % string)


def _get_system_fips_enabled():
    fips_path = "/proc/sys/crypto/fips_enabled"

    try:
        with open(fips_path, "rb") as f:
            data = f.read()
    except OSError as e:
        logger.warning("Unable to determine system FIPS mode: %s", e)
        data = b"0"

    value = int(data)
    if value:
        return True
    else:
        return False


def _get_db_fips_enabled(db_name: str):
    cmd_args = [
        resolve_path("modutil"),
        "-dbdir",
        db_name,  # NSS database
        "-chkfips",
        "true",  # enable/disable fips
    ]

    try:
        return _parse_fips_enabled(subprocess.check_output(cmd_args).decode("utf-8"))
    except subprocess.CalledProcessError as e:
        if e.returncode == FIPS_SWITCH_FAILED_ERR:
            return _parse_fips_enabled(e.output.decode("utf-8"))
        else:
            raise


def _set_fips_mode(enable: bool, db_name: str):
    if enable:
        state = "true"
    else:
        if _get_system_fips_enabled():
            logger.warning("System FIPS enabled, cannot disable FIPS")
            return
        state = "false"

    logging.info("setting fips: %s", state)

    cmd_args = [
        resolve_path("modutil"),
        "-dbdir",
        db_name,  # NSS database
        "-fips",
        state,  # enable/disable fips
        "-force",
    ]

    try:
        subprocess.check_call(cmd_args)
    except subprocess.CalledProcessError as e:
        if enable and e.returncode == FIPS_ALREADY_ON_ERR:
            pass
        elif not enable and e.returncode == FIPS_ALREADY_OFF_ERR:
            pass
        else:
            raise


class CertificateDatabase:
    _DB_PASSWD = "DB_passwd"
    _DB_DIRECTORY = "pki"
    _SERVER_NICKNAME = "test_server"
    _CLIENT_NICKNAME = "test_user"
    _FIPS = False

    _CA_SUBJECT = "CN=Test CA"
    _CA_NICKNAME = "test_ca"
    _KEY_SIZE = 2048
    _VALID_MONTHS = 12
    _CA_PATH_LEN = 2
    _CLIENT_SUBJECT = "CN=test_user"

    def __init__(self, basedir: pathlib.Path):
        self._db_passwd = self._DB_PASSWD

        db_directory = basedir / self._DB_DIRECTORY
        logging.info("Creating clean database directory: %s", db_directory)
        db_directory.mkdir()

        self._db_name = "sql:%s" % db_directory

        self._server_nickname = self._SERVER_NICKNAME
        self._client_nickname = self._CLIENT_NICKNAME
        self._ca_nickname = self._CA_NICKNAME

        _create_database(self.db_passwd, self._db_name)
        _set_fips_mode(self._FIPS, self._db_name)

        serial_file = db_directory / "serial"

        hostname = os.uname()[1]
        server_subject = "CN=%s" % hostname

        with _passwd_file(self.db_passwd) as pwf:
            ca_cert = _create_ca_cert(
                self.db_name,
                pwf,
                serial_file,
                self._CA_SUBJECT,
                self.ca_nickname,
                self._KEY_SIZE,
                self._VALID_MONTHS,
                self._CA_PATH_LEN,
            )
            server_cert = _create_server_cert(
                self.db_name,
                pwf,
                serial_file,
                ca_cert,
                server_subject,
                self.server_nickname,
                self._KEY_SIZE,
                self._VALID_MONTHS,
            )
            client_cert = _create_client_cert(
                self.db_name,
                pwf,
                serial_file,
                ca_cert,
                self._CLIENT_SUBJECT,
                self.client_nickname,
                self._KEY_SIZE,
                self._VALID_MONTHS,
            )

        _add_trusted_certs(self.db_name)

        logging.info("---------- Summary ----------")
        logging.info('NSS database name="%s", password="%s"', self.db_name, self.db_passwd)
        logging.info("system FIPS mode=%s", _get_system_fips_enabled())
        logging.info("DB FIPS mode=%s", _get_db_fips_enabled(self.db_name))
        logging.info('CA nickname="%s", CA subject="%s"', ca_cert, self._CA_SUBJECT)
        logging.info('server nickname="%s", server subject="%s"', server_cert, server_subject)
        logging.info('client nickname="%s", client subject="%s"', client_cert, self._CLIENT_SUBJECT)

    @property
    def db_passwd(self):
        return self._db_passwd

    @property
    def db_name(self):
        return self._db_name

    @property
    def server_nickname(self):
        return self._server_nickname

    @property
    def client_nickname(self):
        return self._client_nickname

    @property
    def ca_nickname(self):
        return self._ca_nickname


@pytest.fixture(scope="class")
def setup_certs(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("certdb")
    return CertificateDatabase(tmp_path)
