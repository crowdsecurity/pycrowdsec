import unittest

from pycrowdsec.cache import Cache
from redislite import Redis


class TestRedisIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.redis = Redis()
        self.cache = Cache()
        self.cache.use_redis = True
        self.cache.redis = self.redis

    def test_store_normal_to_redis(self):
        assert not self.redis.exists("pycrowdsec_cache")
        self.cache.insert("124122", "ban")
        assert self.redis.exists("pycrowdsec_cache")
        assert self.redis.hget("pycrowdsec_cache", b"normal_124122") == b"ban"

    def test_ip_to_redis(self):
        self.cache.insert("1.2.3.4", "captcha")
        self.cache.insert("::ffff", "captcha")
        assert self.redis.hgetall("pycrowdsec_cache") == {
            b"ipv4_4294967295_16909060": b"captcha",
            b"ipv6_340282366920938463463374607431768211455_65535": b"captcha",
        }

    def test_load_from_redis(self):
        self.cache.insert("1.2.3.4", "captcha")
        self.cache.insert("::ffff", "captcha")
        self.cache.insert("TH", "ban")
        old_cache = self.cache

        new_cache = Cache()
        new_cache.redis = self.redis

        new_cache.load_from_redis()
        assert new_cache == old_cache

    def test_delete(self):
        self.cache.insert("1.2.3.4", "captcha")
        self.cache.insert("::ffff", "captcha")
        self.cache.insert("TH", "ban")

        assert len(self.redis.hgetall("pycrowdsec_cache")) == 3

        self.cache.delete("TH")
        assert len(self.redis.hgetall("pycrowdsec_cache")) == 2
        self.cache.delete("1.2.3.4")

        assert len(self.redis.hgetall("pycrowdsec_cache")) == 1
        self.cache.delete("::ffff")

        assert len(self.redis.hgetall("pycrowdsec_cache")) == 0
