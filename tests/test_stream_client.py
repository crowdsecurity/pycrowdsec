import unittest

from pycrowdsec.client import StreamClient

class TestStreamClient(unittest.TestCase):
    def test_process_response(self):
        c = StreamClient("", "", [], 10)
        
        response= {
            "deleted": [
                {
                "duration": "-40h37m10.022674981s",
                "id": 1,
                "origin": "cscli",
                "scenario": "manual 'ban' from 'b436842423d302bb11cb6f1160d6cb30q9EGL7irEAzdUu1z'",
                "scope": "Ip",
                "type": "ban",
                "value": "1.2.3.4"
                },
                {
                "duration": "-37m7.335622172s",
                "id": 97,
                "origin": "CAPI",
                "scenario": "crowdsecurity/http-crawl-non_statics",
                "scope": "Ip",
                "type": "ban",
                "value": "185.220.101.204"
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
                "value": "18.22.10.20"
                },
            ]
        }
        c.process_response(response)
        assert len(c.cache["ip"]) == 1

if __name__ == "__main__":
    unittest.main()