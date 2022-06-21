import ipaddress
import threading
import unittest

from pycrowdsec.client import StreamClient


class TestStreamClient(unittest.TestCase):
    def setUp(self):
        self.client = StreamClient("")

    def test_process_response(self):
        response = {
            "deleted": [
                {
                    "duration": "-40h37m10.022674981s",
                    "id": 1,
                    "origin": "cscli",
                    "scenario": "manual 'ban' from 'b436842423d302bb11cb6f1160d6cb30q9EGL7irEAzdUu1z'",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "18.22.10.20",
                },
                {
                    "duration": "-37m7.335622172s",
                    "id": 97,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/http-crawl-non_statics",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "185.220.101.204",
                },
            ],
            "new": [
                {
                    "duration": "-37m7.335622172s",
                    "id": 97,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/http-crawl-non_statics",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "18.22.10.20",
                },
            ],
        }
        self.client.process_response(response)
        assert len(self.client.cache) == 1

        response["new"] = None
        self.client.process_response(response)
        assert len(self.client.cache) == 0

    def test_read_write_race(self):
        response = {
            "deleted": [
                {
                    "duration": "-40h37m10.022674981s",
                    "id": 1,
                    "origin": "cscli",
                    "scenario": "manual 'ban' from 'b436842423d302bb11cb6f1160d6cb30q9EGL7irEAzdUu1z'",
                    "scope": "Ip",
                    "type": "ban",
                    "value": str(ipaddress.IPv4Address(v)),
                }
                for v in range(100)
            ],
            "new": [
                {
                    "duration": "-37m7.335622172s",
                    "id": 97,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/http-crawl-non_statics",
                    "scope": "Ip",
                    "type": "ban",
                    "value": str(ipaddress.IPv4Address(v)),
                }
                for v in range(100)
            ],
        }

        def response_filler():
            for _ in range(100):
                self.client.process_response(response)

        t = threading.Thread(target=response_filler)
        t.start()
        for _ in range(1000):
            self.client.get_current_decisions()
