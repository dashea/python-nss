import pytest

import nss.nss as nss


class TestCertName:
    subject_name = "CN=www.redhat.com,OU=Web Operations,O=Red Hat Inc,L=Raleigh,ST=North Carolina,C=US"
    cn_name = "www.redhat.com"
    ou_name = "Web Operations"
    o_name = "Red Hat Inc"
    l_name = "Raleigh"
    st_name = "North Carolina"
    c_name = "US"

    @classmethod
    def setup_class(cls):
        nss.nss_init_nodb()

    @classmethod
    def teardown_class(cls):
        nss.nss_shutdown()

    def test_ava_from_name(self):
        ava = nss.AVA("cn", self.cn_name)
        assert str(ava) == ("CN=%s" % self.cn_name)

    def test_ava_from_oid_tag(self):
        ava = nss.AVA(nss.SEC_OID_AVA_COMMON_NAME, self.cn_name)
        assert str(ava) == ("CN=%s" % self.cn_name)
        with pytest.raises(ValueError):
            nss.AVA(nss.SEC_OID_UNKNOWN, self.cn_name)

    def test_ava_from_oid_string(self):
        ava = nss.AVA("2.5.4.3", self.cn_name)
        assert str(ava) == ("CN=%s" % self.cn_name)

        with pytest.raises(ValueError):
            nss.oid_tag("OID.99.99.99.99")

        with pytest.raises(KeyError):
            nss.AVA("foo", self.cn_name)

    def test_oid_dotted_decimal(self):
        assert nss.oid_dotted_decimal(nss.SEC_OID_AVA_COMMON_NAME) == "OID.2.5.4.3"
        assert nss.oid_tag("OID.2.5.4.3") == nss.SEC_OID_AVA_COMMON_NAME
        assert nss.oid_tag("2.5.4.3") == nss.SEC_OID_AVA_COMMON_NAME
        with pytest.raises(ValueError):
            nss.oid_tag("OID.99.99.99.99")

    def test_ava_from_bad_type(self):
        with pytest.raises(TypeError):
            nss.AVA((), self.cn_name)

    def test_ava_compare(self):
        cn_ava1 = nss.AVA("cn", self.cn_name)
        cn_ava2 = nss.AVA("cn", self.cn_name)
        cn_ava3 = nss.AVA("cn", self.cn_name + "A")
        ou_ava = nss.AVA("ou", self.ou_name)

        assert cn_ava1 == cn_ava2
        assert cn_ava1 < ou_ava
        assert cn_ava1 < cn_ava3

    def test_rdn_compare(self):
        cn_rdn1 = nss.RDN(nss.AVA("cn", self.cn_name))
        cn_rdn2 = nss.RDN(nss.AVA("cn", self.cn_name))
        cn_rdn3 = nss.RDN(nss.AVA("cn", self.cn_name + "A"))
        ou_rdn = nss.RDN(nss.AVA("ou", self.ou_name))

        assert cn_rdn1 == cn_rdn2
        assert cn_rdn1 < ou_rdn
        assert cn_rdn1 < cn_rdn3

    def test_rdn_create(self):
        cn_ava = nss.AVA("cn", self.cn_name)
        ou_ava = nss.AVA("ou", self.ou_name)

        rdn = nss.RDN()
        assert len(rdn) == 0
        assert str(rdn) == ""

        rdn = nss.RDN(cn_ava)
        assert len(rdn) == 1
        assert str(rdn) == ("CN=%s" % self.cn_name)
        assert rdn[0] == cn_ava
        assert rdn["cn"] == [cn_ava]

        rdn = nss.RDN(cn_ava, ou_ava)
        assert len(rdn) == 2
        assert str(rdn) == ("CN=%s+OU=%s" % (self.cn_name, self.ou_name))

        assert rdn[0] == cn_ava
        assert rdn[1] == ou_ava

        i = 0
        for ava in rdn:
            if i == 0:
                assert ava == cn_ava
            elif i == 1:
                assert ava == ou_ava
            else:
                pytest.fail("excess ava's")
            i += 1

        assert list(rdn) == [cn_ava, ou_ava]
        assert rdn[:] == [cn_ava, ou_ava]

        assert rdn["cn"] == [cn_ava]
        assert rdn["ou"] == [ou_ava]

        assert str(rdn[0]) == "CN=%s" % self.cn_name
        assert str(rdn[1]) == "OU=%s" % self.ou_name

        assert rdn["2.5.4.3"] == [cn_ava]

        assert rdn.has_key("cn")
        assert "cn" in rdn

        assert rdn.has_key("2.5.4.3")
        assert "2.5.4.3" in rdn

        assert not rdn.has_key("st")
        assert "st" not in rdn

        assert list(rdn) == [cn_ava, ou_ava]
        assert rdn[0:2] == [cn_ava, ou_ava]

        i = 0
        for ava in rdn:
            if i == 0:
                assert rdn[i] == cn_ava
            if i == 1:
                assert rdn[i] == ou_ava
            i = i + 1

        with pytest.raises(KeyError):
            _ = rdn["st"]

        with pytest.raises(KeyError):
            _ = rdn["junk"]

    def test_name(self):
        cn_rdn = nss.RDN(nss.AVA("cn", self.cn_name))
        ou_rdn = nss.RDN(nss.AVA("ou", self.ou_name))
        o_rdn = nss.RDN(nss.AVA("o", self.o_name))
        l_rdn = nss.RDN(nss.AVA("l", self.l_name))
        st_rdn = nss.RDN(nss.AVA("st", self.st_name))
        c_rdn = nss.RDN(nss.AVA("c", self.c_name))

        name = nss.DN(self.subject_name)
        assert str(name) == self.subject_name

        assert name[0] == c_rdn
        assert name[1] == st_rdn
        assert name[2] == l_rdn
        assert name[3] == o_rdn
        assert name[4] == ou_rdn
        assert name[5] == cn_rdn

        assert len(name) == 6

        i = 0
        for rdn in name:
            if i == 0:
                assert rdn == c_rdn
            elif i == 1:
                assert rdn == st_rdn
            elif i == 2:
                assert rdn == l_rdn
            elif i == 3:
                assert rdn == o_rdn
            elif i == 4:
                assert rdn == ou_rdn
            elif i == 5:
                assert rdn == cn_rdn
            else:
                pytest.fail("excess rdn's")
            i += 1

        assert list(name) == [c_rdn, st_rdn, l_rdn, o_rdn, ou_rdn, cn_rdn]
        assert name[:] == [c_rdn, st_rdn, l_rdn, o_rdn, ou_rdn, cn_rdn]

        assert name["c"] == [c_rdn]
        assert name["st"] == [st_rdn]
        assert name["l"] == [l_rdn]
        assert name["o"] == [o_rdn]
        assert name["ou"] == [ou_rdn]
        assert name["cn"] == [cn_rdn]

        assert name.email_address is None
        assert name.common_name == self.cn_name
        assert name.country_name == self.c_name
        assert name.locality_name == self.l_name
        assert name.state_name == self.st_name
        assert name.org_name == self.o_name
        assert name.dc_name is None
        assert name.org_unit_name == self.ou_name
        assert name.cert_uid is None

        name = nss.DN()
        assert str(name) == ""

        name = nss.DN([])
        assert str(name) == ""

        name = nss.DN(())
        assert str(name) == ""

        name = nss.DN("")
        assert str(name) == ""

        with pytest.raises(TypeError):
            nss.DN(1)

        name.add_rdn(cn_rdn)
        assert name[0] == cn_rdn
        assert name["cn"] == [cn_rdn]
        assert str(name) == ("CN=%s" % self.cn_name)

        name.add_rdn(ou_rdn)
        assert name[0] == cn_rdn
        assert name[1] == ou_rdn
        assert name["cn"] == [cn_rdn]
        assert name["ou"] == [ou_rdn]
        assert str(name) == ("OU=%s,CN=%s" % (self.ou_name, self.cn_name))

        name = nss.DN(cn_rdn, ou_rdn)
        assert name[0] == cn_rdn
        assert name[1] == ou_rdn
        assert name["cn"] == [cn_rdn]
        assert name["ou"] == [ou_rdn]
        assert str(name) == ("OU=%s,CN=%s" % (self.ou_name, self.cn_name))

        assert name.has_key("cn")
        assert "cn" in name

        assert name.has_key("ou")
        assert "ou" in name

        assert not name.has_key("st")
        assert "st" not in name

    def test_oid(self):
        assert nss.oid_str("2.5.4.3") == "X520 Common Name"
        assert nss.oid_str(nss.SEC_OID_AVA_COMMON_NAME) == "X520 Common Name"
        assert nss.oid_str("SEC_OID_AVA_COMMON_NAME") == "X520 Common Name"
        assert nss.oid_str("AVA_COMMON_NAME") == "X520 Common Name"
        assert nss.oid_str("cn") == "X520 Common Name"

        assert nss.oid_tag_name("2.5.4.3") == "SEC_OID_AVA_COMMON_NAME"
        assert nss.oid_tag_name(nss.SEC_OID_AVA_COMMON_NAME) == "SEC_OID_AVA_COMMON_NAME"
        assert nss.oid_tag_name("SEC_OID_AVA_COMMON_NAME") == "SEC_OID_AVA_COMMON_NAME"
        assert nss.oid_tag_name("AVA_COMMON_NAME") == "SEC_OID_AVA_COMMON_NAME"
        assert nss.oid_tag_name("cn") == "SEC_OID_AVA_COMMON_NAME"

        assert nss.oid_dotted_decimal("2.5.4.3") == "OID.2.5.4.3"
        assert nss.oid_dotted_decimal(nss.SEC_OID_AVA_COMMON_NAME) == "OID.2.5.4.3"
        assert nss.oid_dotted_decimal("SEC_OID_AVA_COMMON_NAME") == "OID.2.5.4.3"
        assert nss.oid_dotted_decimal("AVA_COMMON_NAME") == "OID.2.5.4.3"
        assert nss.oid_dotted_decimal("cn") == "OID.2.5.4.3"

        assert nss.oid_tag("2.5.4.3") == nss.SEC_OID_AVA_COMMON_NAME
        assert nss.oid_tag(nss.SEC_OID_AVA_COMMON_NAME) == nss.SEC_OID_AVA_COMMON_NAME
        assert nss.oid_tag("SEC_OID_AVA_COMMON_NAME") == nss.SEC_OID_AVA_COMMON_NAME
        assert nss.oid_tag("AVA_COMMON_NAME") == nss.SEC_OID_AVA_COMMON_NAME
        assert nss.oid_tag("cn") == nss.SEC_OID_AVA_COMMON_NAME

    def test_multi_value(self):
        subject = "CN=www.redhat.com,OU=engineering,OU=boston+OU=westford,C=US"
        cn_ava = nss.AVA("cn", self.cn_name)
        ou1_ava1 = nss.AVA("ou", "boston")
        ou1_ava2 = nss.AVA("ou", "westford")
        ou2_ava1 = nss.AVA("ou", "engineering")
        c_ava = nss.AVA("c", self.c_name)

        cn_rdn = nss.RDN(cn_ava)
        ou1_rdn = nss.RDN(ou1_ava1, ou1_ava2)
        ou2_rdn = nss.RDN(ou2_ava1)
        c_rdn = nss.RDN(c_ava)

        name = nss.DN(subject)

        assert len(name) == 4

        assert name["cn"] == [cn_rdn]
        assert name["ou"] == [ou1_rdn, ou2_rdn]
        assert name["c"] == [c_rdn]

        rdn = name["ou"][0]
        assert len(rdn) == 2
        assert rdn == ou1_rdn
        assert rdn[0] == ou1_ava1
        assert rdn[1] == ou1_ava2
        assert list(rdn) == [ou1_ava1, ou1_ava2]
        assert rdn[:] == [ou1_ava1, ou1_ava2]
