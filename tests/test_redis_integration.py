import unittest

from redislite import Redis

from pycrowdsec.cache import RedisCache


class TestRedisIntegration(unittest.TestCase):
    def setUp(self):
        self.redis = Redis()
        self.cache = RedisCache(redis_connection=self.redis)

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

    def test_delete(self):
        self.cache.insert("1.2.3.4", "captcha")
        self.cache.insert("::ffff", "captcha")
        self.cache.insert("TH", "ban")

        assert self.redis.hlen("pycrowdsec_cache") == 3

        self.cache.delete("TH")
        assert self.redis.hlen("pycrowdsec_cache") == 2
        self.cache.delete("1.2.3.4")

        assert self.redis.hlen("pycrowdsec_cache") == 1
        self.cache.delete("::ffff")

        assert self.redis.hlen("pycrowdsec_cache") == 0

    def test_get_all(self):
        self.cache.insert("1.2.3.4", "captcha")
        self.cache.insert("::ffff", "captcha")
        self.cache.insert("TH", "ban")

        resp = self.cache.get_all()
        assert resp["1.2.3.4/32"] == "captcha"
        assert resp["TH"] == "ban"
        assert resp["::ffff/128"] == "captcha"
