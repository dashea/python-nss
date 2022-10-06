import nss.nss as nss

# -------------------------------------------------------------------------------
class TestVersion:
    @classmethod
    def setup_class(cls):
        nss.nss_init_nodb()

    @classmethod
    def teardown_class(cls):
        nss.nss_shutdown()

    def test_version(self):
        version = nss.nss_get_version()
        assert nss.nss_version_check(version)


class TestShutdownCallback:
    def test_shutdown_callback(self):
        int_value = 43
        str_value = "foobar"
        count = 0
        dict_value = {"count": count}

        def shutdown_callback(nss_data, i, s, d):
            assert isinstance(nss_data, dict)

            assert isinstance(i, int)
            assert i == int_value

            assert isinstance(s, str)
            assert s == str_value

            assert isinstance(d, dict)
            assert d == dict_value
            d["count"] += 1
            return True

        nss.nss_init_nodb()
        nss.set_shutdown_callback(shutdown_callback, int_value, str_value, dict_value)
        nss.nss_shutdown()
        assert dict_value["count"] == count + 1

        # Callback should not be invoked again after shutdown
        nss.nss_init_nodb()
        nss.nss_shutdown()
        assert dict_value["count"] == count + 1

        # Callback should not be invoked if cleared
        nss.nss_init_nodb()
        nss.set_shutdown_callback(shutdown_callback, int_value, str_value, dict_value)
        nss.set_shutdown_callback(None)
        nss.nss_shutdown()
        assert dict_value["count"] == count + 1
