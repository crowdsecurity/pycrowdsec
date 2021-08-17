import threading
from time import sleep

import requests

from pycrowdsec.cache import Cache


class StreamClient:
    def __init__(
        self,
        api_key,
        lapi_url="http://localhost:8080/",
        interval=15,
        user_agent="CrowdSec-Python-StreamClient",
        scopes=["ip", "range"],
    ):
        """
        Parameters
        ----------
        api_key(Required) : str
            Bouncer key for CrowdSec API.
        lapi_url(Optional) : str
            Base URL of CrowdSec API. Default is http://localhost:8080/ .
        interval(Optional) : int
            Query the CrowdSec API every "interval" second
        user_agent(Optional) : str
            User agent to use while calling the API.
        scopes(Optional) : List[str]
            List of decision scopes which shall be fetched. Default is ["ip", "range"]
        """
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
            {"X-Api-Key": self.api_key, "User-Agent": self.user_agent},
        )
        first_time = "true"
        while True:
            sleep(self.interval)
            resp = session.get(
                url=f"{self.lapi_url}v1/decisions/stream",
                params={
                    "startup": first_time,
                    "scopes": ",".join(self.scopes),
                },
            )
            self.process_response(resp.json())
            first_time = "false"

    def process_response(self, response):
        if response["new"] is None:
            response["new"] = []

        if response["deleted"] is None:
            response["deleted"] = []

        for decision in response["deleted"]:
            self.cache.delete(decision["value"])

        for decision in response["new"]:
            self.cache.insert(decision["value"], decision["type"])

    def run(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
