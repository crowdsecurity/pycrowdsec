import ipaddress
import threading
import unittest

from pycrowdsec.client import StreamDecisionClient


class TestStreamDecisionClient(unittest.TestCase):
    def setUp(self):
        self.client = StreamDecisionClient("abcd")

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
        assert len(list(self.client.get_new_decision())) == 1
        assert len(list(self.client.get_deleted_decision())) == 2

        assert len(list(self.client.get_new_decision())) == 0
        assert len(list(self.client.get_deleted_decision())) == 0

    def test_empty(self):
        assert self.client.new_decisions.empty() == True
        assert self.client.deleted_decisions.empty() == True

        for _ in self.client.get_deleted_decision():
            pass

        for _ in self.client.get_new_decision():
            pass

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
            list(self.client.get_deleted_decision())
            list(self.client.get_new_decision())
