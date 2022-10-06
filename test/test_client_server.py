import logging
import os
import pathlib
import signal
import tempfile
import time

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl
from setup_certs import CertificateDatabase

# -----------------------------------------------------------------------------
port = 1234
timeout_secs = 10
sleep_time = 10

logger = logging.getLogger()

# -----------------------------------------------------------------------------
# Callback Functions
# -----------------------------------------------------------------------------


def password_callback(slot, retry, password):
    if not password:
        raise RuntimeError("password not set in callback")
    return password


def handshake_callback(sock):
    logger.debug("-- handshake complete --")
    logger.debug("peer: %s", sock.get_peer_name())
    logger.debug("negotiated host: %s", sock.get_negotiated_host())
    logger.debug("")
    logger.debug("%s", sock.connection_info_str())
    logger.debug("-- handshake complete --")
    logger.debug("")


def auth_certificate_callback(sock, check_sig, is_server, certdb):
    logger.debug("auth_certificate_callback: check_sig=%s is_server=%s", check_sig, is_server)
    cert_is_valid = False

    cert = sock.get_peer_certificate()
    pin_args = sock.get_pkcs11_pin_arg()
    if pin_args is None:
        pin_args = ()

    # Define how the cert is being used based upon the is_server flag.  This may
    # seem backwards, but isn't. If we're a server we're trying to validate a
    # client cert. If we're a client we're trying to validate a server cert.
    if is_server:
        intended_usage = nss.certificateUsageSSLClient
    else:
        intended_usage = nss.certificateUsageSSLServer

    try:
        # If the cert fails validation it will raise an exception, the errno attribute
        # will be set to the error code matching the reason why the validation failed
        # and the strerror attribute will contain a string describing the reason.
        approved_usage = cert.verify_now(certdb, check_sig, intended_usage, *pin_args)
    except Exception as e:
        logger.error("auth_certificate_callback: %s", e)
        cert_is_valid = False
        logger.debug("Returning cert_is_valid = %s", cert_is_valid)
        return cert_is_valid

    logger.debug("approved_usage = %s", ", ".join(nss.cert_usage_flags(approved_usage)))

    # Is the intended usage a proper subset of the approved usage
    if approved_usage & intended_usage:
        cert_is_valid = True
    else:
        cert_is_valid = False

    # If this is a server, we're finished
    if is_server or not cert_is_valid:
        logger.debug("Returning cert_is_valid = %s", cert_is_valid)
        return cert_is_valid

    # Certificate is OK.  Since this is the client side of an SSL
    # connection, we need to verify that the name field in the cert
    # matches the desired hostname.  This is our defense against
    # man-in-the-middle attacks.

    hostname = sock.get_hostname()
    logger.debug("verifying socket hostname (%s) matches cert subject (%s)", hostname, cert.subject)
    try:
        # If the cert fails validation it will raise an exception
        cert_is_valid = cert.verify_hostname(hostname)
    except Exception as e:
        logger.error("auth_certificate_callback: %s", e)
        cert_is_valid = False
        logger.debug("Returning cert_is_valid = %s", cert_is_valid)
        return cert_is_valid

    logger.debug("Returning cert_is_valid = %s", cert_is_valid)
    return cert_is_valid


def client_auth_data_callback(ca_names, chosen_nickname, password, certdb):
    cert = None
    if chosen_nickname:
        try:
            cert = nss.find_cert_from_nickname(chosen_nickname, password)
            priv_key = nss.find_key_by_any_cert(cert, password)
            logger.debug("client cert:\n%s", cert)
            return cert, priv_key
        except NSPRError as e:
            logger.error("client_auth_data_callback: %s", e)
            return False
    else:
        nicknames = nss.get_cert_nicknames(certdb, nss.SEC_CERT_NICKNAMES_USER)
        for nickname in nicknames:
            try:
                cert = nss.find_cert_from_nickname(nickname, password)
                logger.debug("client cert:\n%s", cert)
                if cert.check_valid_times():
                    if cert.has_signer_in_ca_names(ca_names):
                        priv_key = nss.find_key_by_any_cert(cert, password)
                        return cert, priv_key
            except NSPRError as e:
                logger.error("client_auth_data_callback: %s", e)
        return False


# -----------------------------------------------------------------------------
# Client Implementation
# -----------------------------------------------------------------------------


def client(request, client_nickname, password):
    logger.info("client: using SSL")
    hostname = os.uname()[1]
    ssl.set_domestic_policy()

    # Get the IP Address of our server
    addr_info = io.AddrInfo(hostname)

    for net_addr in addr_info:
        net_addr.port = port

        sock = ssl.SSLSocket(net_addr.family)

        # Set client SSL socket options
        sock.set_ssl_option(ssl.SSL_SECURITY, True)
        sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        sock.set_hostname(hostname)

        # Provide a callback which notifies us when the SSL handshake is complete
        sock.set_handshake_callback(handshake_callback)

        # Provide a callback to supply our client certificate info
        sock.set_client_auth_data_callback(
            client_auth_data_callback, client_nickname, password, nss.get_default_certdb()
        )

        # Provide a callback to verify the servers certificate
        sock.set_auth_certificate_callback(auth_certificate_callback, nss.get_default_certdb())

        try:
            logger.debug("client trying connection to: %s", net_addr)
            sock.connect(net_addr, timeout=io.seconds_to_interval(timeout_secs))
            logger.debug("client connected to: %s", net_addr)
            break
        except Exception as e:
            sock.close()
            logger.error("client: connection to: %s failed (%s)", net_addr, e)
    else:
        raise RuntimeError("All connections failed")

    # Talk to the server
    try:
        logger.info('client: sending "%s"', request)
        data = request + "\n"  # newline is protocol record separator
        sock.send(data.encode("utf-8"))
        buf = sock.readline()
        if not buf:
            logger.error("client: lost connection")
            sock.close()
            return
        buf = buf.decode("utf-8")
        buf = buf.rstrip()  # remove newline record separator
        logger.info('client: received "%s"', buf)
    finally:
        try:
            sock.shutdown()
        except Exception as e:
            logger.error("client: %s", e)

        sock.close()
        ssl.clear_session_cache()

    return buf


# -----------------------------------------------------------------------------
# Server Implementation
# -----------------------------------------------------------------------------


def server(server_nickname, password):
    logger.debug("starting server:")

    # Initialize
    # Setup an IP Address to listen on any of our interfaces
    net_addr = io.NetworkAddress(io.PR_IpAddrAny, port)

    logger.info("server: using SSL")
    ssl.set_domestic_policy()
    nss.set_password_callback(password_callback)

    # Perform basic SSL server configuration
    ssl.set_default_cipher_pref(ssl.SSL_RSA_WITH_NULL_MD5, True)
    ssl.config_server_session_id_cache()

    # Get our certificate and private key
    server_cert = nss.find_cert_from_nickname(server_nickname, password)
    priv_key = nss.find_key_by_any_cert(server_cert, password)
    server_cert_kea = server_cert.find_kea_type()

    sock = ssl.SSLSocket(net_addr.family)

    # Set server SSL socket options
    sock.set_pkcs11_pin_arg(password)
    sock.set_ssl_option(ssl.SSL_SECURITY, True)
    sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_SERVER, True)

    sock.set_auth_certificate_callback(auth_certificate_callback, nss.get_default_certdb())

    # Configure the server SSL socket
    sock.config_secure_server(server_cert, priv_key, server_cert_kea)

    # Bind to our network address and listen for clients
    sock.bind(net_addr)
    logger.debug("listening on: %s", net_addr)
    sock.listen()

    while True:
        # Accept a connection from a client
        client_sock, client_addr = sock.accept()
        client_sock.set_handshake_callback(handshake_callback)

        logger.debug("client connect from: %s", client_addr)

        while True:
            try:
                # Handle the client connection
                buf = client_sock.readline()  # newline is protocol record separator
                if not buf:
                    logger.error("server: lost lost connection to %s", client_addr)
                    break
                buf = buf.decode("utf-8")
                buf = buf.rstrip()  # remove newline record separator

                logger.info('server: received "%s"', buf)
                reply = "{%s}" % buf  # echo embedded inside braces
                logger.info('server: sending "%s"', reply)
                data = reply + "\n"  # send echo with record separator
                client_sock.send(data.encode("utf-8"))

                time.sleep(sleep_time)
                client_sock.shutdown()
                client_sock.close()
                break
            except Exception as e:
                logger.error("server: %s", e)
                break
        break

    # Clean up
    sock.shutdown()
    sock.close()
    ssl.shutdown_server_session_id_cache()


# -----------------------------------------------------------------------------


def run_server(certdb):
    pid = os.fork()
    if pid == 0:
        nss.nss_init(certdb.db_name)
        server(certdb.server_nickname, certdb.db_passwd)
        nss.nss_shutdown()
        os._exit(0)
    time.sleep(sleep_time)
    return pid


def cleanup_server(pid):
    wait_pid, _ = os.waitpid(pid, os.WNOHANG)
    if wait_pid == 0:
        os.kill(pid, signal.SIGKILL)


class TestSSL:
    # Do not call nss_init here, set it up separately in client and server
    @classmethod
    def setup_class(cls):
        cls.basedir = tempfile.TemporaryDirectory()
        cls.certdb = CertificateDatabase(pathlib.Path(cls.basedir.name))
        cls.pid = run_server(cls.certdb)

    @classmethod
    def teardown_class(cls):
        del cls.certdb
        cls.basedir.cleanup()
        del cls.basedir
        cleanup_server(cls.pid)
        del cls.pid

    def test_ssl(self):
        nss.nss_init(self.certdb.db_name)
        nss.set_password_callback(password_callback)

        request = "foo"
        nss.nss_init(self.certdb.db_name)
        reply = client(request, self.certdb.client_nickname, self.certdb.db_passwd)
        nss.nss_shutdown()
        assert ("{%s}" % request) == reply
