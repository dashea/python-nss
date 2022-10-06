import logging
import nss.nss as nss

# Helper function for test_digest
def digest_test(name, in_filename, py_digest_ctx, nss_digest_func, hash_oid):
    CHUNK_SIZE = 128
    hash_oid_name = nss.oid_str(hash_oid)
    log = logging.getLogger()

    log.debug(
        "Running test %s: nss_digest_func=%s hash_oid=%s in_filename=%s",
        name,
        nss_digest_func.__name__,
        hash_oid_name,
        in_filename,
    )

    with open(in_filename, "rb") as f:
        ref_data = f.read()

    # Run the system hash function to get a reference result.
    py_digest_ctx.update(ref_data)
    reference_digest = py_digest_ctx.digest()
    reference_digest_hex = py_digest_ctx.hexdigest()
    log.debug("reference_digest\n%s", reference_digest_hex)

    # Run the test with convenience digest function (e.g. nss.sha256_digest, etc.).
    test_digest = nss_digest_func(ref_data)
    test_digest_hex = nss.data_to_hex(test_digest, separator=None)
    log.debug("nss %s\n%s", nss_digest_func.__name__, test_digest_hex)

    assert test_digest == reference_digest, "nss %s test failed reference=%s, test=%s" % (
        nss_digest_func.__name__,
        reference_digest_hex,
        test_digest_hex,
    )

    # Run the test using the generic hash_buf function specifying the hash algorithm.
    test_digest = nss.hash_buf(hash_oid, ref_data)
    test_digest_hex = nss.data_to_hex(test_digest, separator=None)
    log.debug("nss.hash_buf %s\n%s", hash_oid_name, test_digest_hex)
    assert test_digest == reference_digest, "nss.hash_buf %s test failed reference=%s test=%s" % (
        hash_oid_name,
        reference_digest_hex,
        test_digest_hex,
    )

    # Run the test using the lowest level hashing functions by specifying the hash algorithm.
    # The entire input data is supplied all at once in a single call.
    context = nss.create_digest_context(hash_oid)
    context.digest_begin()
    context.digest_op(ref_data)
    test_digest = context.digest_final()
    test_digest_hex = nss.data_to_hex(test_digest, separator=None)
    log.debug("nss.digest_context %s\n%s", hash_oid_name, test_digest_hex)

    assert test_digest == reference_digest, "nss.digest_context %s test failed reference=%s test=%s" % (
        hash_oid_name,
        reference_digest_hex,
        test_digest_hex,
    )

    # Run the test using the lowest level hashing functions by specifying the hash algorithm
    # and feeding 'chunks' of data one at a time to be consumed.
    with open(in_filename, "rb") as in_file:
        context = nss.create_digest_context(hash_oid)
        context.digest_begin()
        while True:
            in_data = in_file.read(CHUNK_SIZE)
            if len(in_data) == 0:
                break
            context.digest_op(in_data)

    test_digest = context.digest_final()
    test_digest_hex = nss.data_to_hex(test_digest, separator=None)
    log.debug("chunked nss.digest_context %s\n%s", hash_oid_name, test_digest_hex)

    assert test_digest == reference_digest, "chunked nss.digest_context %s test failed reference=%s test=%s" % (
        hash_oid_name,
        reference_digest_hex,
        test_digest_hex,
    )
