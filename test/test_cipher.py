import os

import nss.nss as nss

# -------------------------------------------------------------------------------

MECHANISM = nss.CKM_DES_CBC_PAD
PLAIN_TEXT = b"Encrypt me!"
KEY = "e8:a7:7c:e2:05:63:6a:31"
IV = "e4:bb:3b:d3:c3:71:2e:58"
CHUNK_SIZE = 128

# -------------------------------------------------------------------------------


def setup_contexts():
    # Get a PK11 slot based on the cipher
    slot = nss.get_best_slot(MECHANISM)

    key_si = nss.SecItem(nss.read_hex(KEY))
    sym_key = nss.import_sym_key(slot, MECHANISM, nss.PK11_OriginUnwrap, nss.CKA_ENCRYPT, key_si)

    iv_data = nss.read_hex(IV)
    iv_si = nss.SecItem(iv_data)
    iv_param = nss.param_from_iv(MECHANISM, iv_si)

    # Create an encoding context
    encoding_ctx = nss.create_context_by_sym_key(MECHANISM, nss.CKA_ENCRYPT, sym_key, iv_param)

    # Create a decoding context
    decoding_ctx = nss.create_context_by_sym_key(MECHANISM, nss.CKA_DECRYPT, sym_key, iv_param)

    return encoding_ctx, decoding_ctx


# -------------------------------------------------------------------------------


class TestCipher:
    @classmethod
    def setup_class(cls):
        nss.nss_init_nodb()

    @classmethod
    def teardown_class(cls):
        nss.nss_shutdown()

    def test_string(self):
        (encoding_ctx, decoding_ctx) = setup_contexts()

        # Encode the plain text by feeding it to cipher_op getting cipher text back.
        # Append the final bit of cipher text by calling digest_final
        cipher_text = encoding_ctx.cipher_op(PLAIN_TEXT)
        cipher_text += encoding_ctx.digest_final()

        # Decode the cipher text by feeding it to cipher_op getting plain text back.
        # Append the final bit of plain text by calling digest_final
        decoded_text = decoding_ctx.cipher_op(cipher_text)
        decoded_text += decoding_ctx.digest_final()

        # Validate the encryption/decryption by comparing the decoded text with
        # the original plain text, they should match.
        assert decoded_text == PLAIN_TEXT

        assert cipher_text != PLAIN_TEXT

    def test_file(self, tmp_path):
        (encoding_ctx, decoding_ctx) = setup_contexts()

        encrypted_filename = tmp_path / "encrypted"
        decrypted_filename = tmp_path / "decrypted"

        in_filename = os.path.abspath(__file__)
        with open(in_filename, "rb") as in_file, open(encrypted_filename, "wb") as encrypted_file:
            # Encode the data read from a file in chunks
            while True:
                # Read a chunk of data until EOF, encrypt it and write the encrypted data
                in_data = in_file.read(CHUNK_SIZE)
                if len(in_data) == 0:  # EOF
                    break
                encrypted_data = encoding_ctx.cipher_op(in_data)
                encrypted_file.write(encrypted_data)
            # Done encoding the input, get the final encoded data, write it, close files
            encrypted_data = encoding_ctx.digest_final()
            encrypted_file.write(encrypted_data)

        # Decode the encoded file in a similar fashion
        with open(encrypted_filename, "rb") as encrypted_file, open(decrypted_filename, "wb") as decrypted_file:
            while True:
                # Read a chunk of data until EOF, encrypt it and write the encrypted data
                in_data = encrypted_file.read(CHUNK_SIZE)
                if len(in_data) == 0:  # EOF
                    break
                decrypted_data = decoding_ctx.cipher_op(in_data)
                decrypted_file.write(decrypted_data)
            # Done encoding the input, get the final encoded data, write it, close files
            decrypted_data = decoding_ctx.digest_final()
            decrypted_file.write(decrypted_data)

        # Validate the encryption/decryption by comparing the decoded text with
        # the original plain text, they should match.
        with open(in_filename, "rb") as f:
            in_data = f.read()
        with open(encrypted_filename, "rb") as f:
            encrypted_data = f.read()
        with open(decrypted_filename, "rb") as f:
            decrypted_data = f.read()

        assert decrypted_data == in_data
        assert encrypted_data != in_data
