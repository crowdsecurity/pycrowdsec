import random
from unittest import TestCase

from pycrowdsec.cache import Cache


class TestIPv4Cache(TestCase):
    def setUp(self):
        self.cache = Cache()

    def test_insert_delete(self):
        self.cache.insert("1.2.3.4", "ban")
        assert self.cache.get("1.2.3.4") == "ban"
        assert self.cache.get("1.2.3.5") is None

        self.cache.delete("1.2.3.4")
        assert self.cache.get("1.2.3.4") is None
        assert self.cache.get("1.2.3.5") is None

    def test_range_simple_range(self):
        self.cache.insert("0.0.0.0/24", "ban")
        for i in range(256):
            ip = f"0.0.0.{i}"
            with self.subTest(ip=ip):
                assert self.cache.get(ip) == "ban"

        assert self.cache.get(f"0.0.1.0") is None
        assert self.cache.get("::") is None

        self.cache.delete("0.0.0.0/24")
        for i in range(256):
            assert self.cache.get(f"0.0.0.{i}") is None

    def test_range_all_match(self):
        self.cache.insert("0.0.0.0/0", "ban")
        ip_parts = [str(i) for i in range(256)]
        for _ in range(20):
            ip = ".".join(random.choices(ip_parts, k=4))
            with self.subTest(ip=ip):
                assert self.cache.get(ip) == "ban"

        self.cache.delete("0.0.0.0/0")
        for _ in range(20):
            ip = ".".join(random.choices(ip_parts, k=4))
            with self.subTest(ip=ip):
                assert self.cache.get(ip) is None

    def test_range_overlap(self):
        def assert_state(a, b, c):
            assert self.cache.get("0.0.1.2") == a
            assert self.cache.get("0.0.255.255") == b
            self.cache.get("0.1.255.255") == c

        assert_state(None, None, None)
        self.cache.insert("0.0.0.0/16", "ban")
        assert_state("ban", "ban", None)

        self.cache.insert("0.0.0.0/8", "captcha")
        assert_state("ban", "ban", "captcha")

        self.cache.insert("0.0.1.0/24", "throttle")
        assert_state("throttle", "ban", "captcha")

        self.cache.delete("0.0.1.0/24")
        assert_state("ban", "ban", "captcha")

        self.cache.delete("0.0.0.0/8")
        assert_state("ban", "ban", None)

        self.cache.delete("0.0.0.0/16")
        assert_state(None, None, None)


class TestIPv6Cache(TestCase):
    def setUp(self):
        self.cache = Cache()

    def test_insert_delete(self):
        assert self.cache.get("::") is None
        self.cache.insert("::", "ban")
        assert self.cache.get("::") == "ban"
        assert self.cache.get("1::") is None

        self.cache.delete("::")
        assert self.cache.get("1.2.3.4") is None
        assert self.cache.get("1.2.3.5") is None

    def test_range_simple_range(self):
        self.cache.insert("::/112", "ban")
        ips_to_check = random.choices(range(65535), k=100)
        for i in ips_to_check:
            ip = f"::{format(i, 'x')}"
            with self.subTest(ip=ip):
                assert self.cache.get(ip) == "ban"

        assert self.cache.get(f"1::") is None
        assert self.cache.get("0.0.0.0") is None

        self.cache.delete("::/112")
        for i in ips_to_check:
            ip = f"::{format(i, 'x')}"
            with self.subTest(ip=ip):
                assert self.cache.get(ip) is None

    def test_range_all_match(self):
        self.cache.insert("::/0", "ban")
        ip_parts = [format(i, "x") for i in range(65535)]
        for _ in range(20):
            ip = ":".join(random.choices(ip_parts, k=8))
            with self.subTest(ip=ip):
                assert self.cache.get(ip) == "ban"

        self.cache.delete("::/0")
        for _ in range(20):
            ip = ":".join(random.choices(ip_parts, k=8))
            with self.subTest(ip=ip):
                assert self.cache.get(ip) is None

    def test_range_overlap(self):
        def assert_state(a, b, c):
            assert self.cache.get("::ffff") == a
            assert self.cache.get("::1:ffff") == b
            self.cache.get("::1:ffff:ffff") == c

        assert_state(None, None, None)
        self.cache.insert("::/112", "ban")
        assert_state("ban", None, None)

        self.cache.insert("::/98", "captcha")
        assert_state("ban", "captcha", None)

        self.cache.insert("::/82", "throttle")
        assert_state("ban", "captcha", "throttle")

        self.cache.insert("::ffff/128", "block")
        assert_state("block", "captcha", "throttle")

        self.cache.delete("::ffff/128")
        assert_state("ban", "captcha", "throttle")

        self.cache.delete("::/82")
        assert_state("ban", "captcha", None)

        self.cache.delete("::/98")
        assert_state("ban", None, None)

        self.cache.delete("::/112")
        assert_state(None, None, None)


class TestCache(TestCase):
    def setUp(self):
        self.cache = Cache()

    def test_non_ip_items(self):
        assert self.cache.get("TM") is None

        self.cache.insert("TM", "ban")
        assert self.cache.get("TM") == "ban"

        self.cache.insert("TM", "captcha")
        assert self.cache.get("TM") == "captcha"

        self.cache.delete("TM")
        assert self.cache.get("TM") is None

    def test_ip_items(self):
        assert self.cache.get("::ffff") is None

        self.cache.insert("::/112", "ban")
        assert self.cache.get("::ffff") == "ban"
        assert self.cache.get("::abcd") == "ban"
        assert self.cache.get("::abcd:abcd") is None

        assert self.cache.get("1.2.3.4") is None
        self.cache.insert("1.2.0.0/16", "ban")
        assert self.cache.get("1.2.3.4") == "ban"

        self.cache.delete("1.2.0.0/16")
        assert self.cache.get("1.2.3.4") is None

    def test_get_all(self):
        self.cache.insert("CN", "captcha")
        self.cache.insert("1.2.3.4", "ban")
        self.cache.insert("1.2.3.0/24", "ban")
        self.cache.insert("ffff::/24", "ban")

        resp = self.cache.get_all()
        assert resp["ffff::/24"] == "ban"
        assert resp["1.2.3.0/24"] == "ban"
        assert resp["1.2.3.4/32"] == "ban"
        assert resp["CN"] == "captcha"
