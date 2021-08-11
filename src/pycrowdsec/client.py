import threading
from time import sleep

import requests

from pycrowdsec.cache import Cache

class StreamClient:
    def __init__(self, api_key, lapi_url, scopes, interval, user_agent="CrowdSec-Python-StreamClient"):
        self.cache = Cache()
        self.api_key = api_key
        self.scopes = scopes
        self.interval = int(interval)
        self.lapi_url = lapi_url
        self.user_agent = user_agent
    
    def get_action_for(self, item):
        return self.cache.get(item)

    def _run(self):
        session = requests.Session()
        session.headers.update(
            {
                "X-Api-Key": self.api_key,
                "User-Agent": self.user_agent
            },
        )
        first_time = "true"
        while True:
            sleep(self.interval)
            resp = session.get(url=f"{self.lapi_url}v1/decisions/stream",
            params={
                "startup": first_time
            })
            self.process_response(resp.json())
            first_time = "false"

    def process_response(self, response):
        if response["new"] is None : 
            response["new"] = []

        if response["deleted"] is None : 
            response["deleted"] = []

        for decision in response["deleted"]:
            self.cache.delete(decision["value"])

        for decision in response["new"]:
            self.cache.insert(decision["value"], decision["type"])

    def run(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
