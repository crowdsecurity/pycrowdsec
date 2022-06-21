import logging
import threading
from importlib.metadata import version
from time import sleep

import requests

from pycrowdsec.cache import Cache, RedisCache

logger = logging.getLogger(__name__)


class QueryClient:
    def __init__(
        self,
        api_key,
        lapi_url="http://localhost:8080/",
        user_agent=f"python-bouncer/{version('pycrowdsec')}",
    ):
        """
        Parameters
        ----------
        api_key(Required) : str
            Bouncer key for CrowdSec API.
        lapi_url(Optional) : str
            Base URL of CrowdSec API. Default is http://localhost:8080/ .
        """

        self.api_key = api_key
        self.lapi_url = lapi_url
        self.user_agent = user_agent

    def get_action_for(self, item):
        resp = requests.get(
            f"{self.lapi_url}v1/decisions?ip={item}", headers={"X-Api-Key": self.api_key}
        ).json()
        if resp:
            return max(resp, key=lambda d: d["id"])["type"]


class StreamClient:
    def __init__(
        self,
        api_key,
        lapi_url="http://localhost:8080/",
        interval=15,
        user_agent=f"python-bouncer/{version('pycrowdsec')}",
        scopes=["ip", "range"],
        **kwargs,
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
        if "redis_connection" in kwargs:
            self.cache = RedisCache(redis_connection=kwargs["redis_connection"])
        else:
            self.cache = Cache()

        self.api_key = api_key
        self.scopes = scopes
        self.interval = int(interval)
        self.lapi_url = lapi_url
        self.user_agent = user_agent
        self.death_reason = None

    def get_action_for(self, item):
        return self.cache.get(item)

    def get_current_decisions(self):
        return self.cache.get_all()

    def _run(self):
        session = requests.Session()
        session.headers.update(
            {"X-Api-Key": self.api_key, "User-Agent": self.user_agent},
        )
        first_time = "true"
        while True:
            try:
                resp = session.get(
                    url=f"{self.lapi_url}v1/decisions/stream",
                    params={
                        "startup": first_time,
                        "scopes": ",".join(self.scopes),
                    },
                )
                resp.raise_for_status()
            except Exception as e:
                logger.error(f"pycrowdsec got error {e}")
                if first_time == "true":
                    self.death_reason = e
                    return
                sleep(self.interval)
                continue
            self.process_response(resp.json())
            first_time = "false"
            sleep(self.interval)

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
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def is_running(self):
        return self.t.is_alive()
