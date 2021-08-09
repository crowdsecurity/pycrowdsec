import threading
from time import sleep

import requests

class StreamClient:
    def __init__(self, api_key, lapi_url, scopes, interval, user_agent="CrowdSec-Python-Client"):
        self.action_by_item = {}
        self.api_key = api_key
        self.scopes = scopes
        #TODO use https://github.com/wroberts/pytimeparse
        self.interval = int(interval)
        self.lapi_url = lapi_url
        self.user_agent = user_agent

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
        print(response)
        if response["new"] is None : 
            response["new"] = []

        if response["deleted"] is None : 
            response["deleted"] = []

        for decision in response["new"]:
            self.action_by_item[decision["value"]] = decision["type"]

        for decision in response["deleted"]:
            if decision["value"] in self.action_by_item:
                del self.action_by_item[decision["value"]]


    def run(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()


if __name__ == "__main__":
    c = StreamClient(
        lapi_url="http://localhost:8080/",
        api_key="1ae6f423ec73130e87773f2c0c2477fe",
        interval=5,
        scopes="",
    )
    c.run()
    sleep(600)
