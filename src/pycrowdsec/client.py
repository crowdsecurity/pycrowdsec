import logging
import queue
import threading
from abc import ABC, abstractmethod

try:
    from importlib import metadata
except ImportError:  # for Python<3.8
    import importlib_metadata as metadata

__version__ = metadata.version("pycrowdsec")

from time import sleep

import requests

from pycrowdsec.cache import Cache, RedisCache

logger = logging.getLogger(__name__)


def create_session(api_key, insecure_skip_verify, key_path, cert_path, ca_cert_path, user_agent):
    session = requests.Session()
    session.verify = not insecure_skip_verify
    if api_key:
        session.headers.update(
            {"X-Api-Key": api_key, "User-Agent": user_agent},
        )
    else:
        if ca_cert_path:
            session.verify = ca_cert_path
        session.cert = (cert_path, key_path)
    return session


class QueryClient:
    def __init__(
        self,
        api_key="",
        lapi_url="http://localhost:8080/",
        user_agent=f"python-bouncer/{metadata.version('pycrowdsec')}",
        insecure_skip_verify=False,
        key_path="",
        cert_path="",
        ca_cert_path="",
    ):
        """
        Parameters
        ----------
        api_key(Required) : str
            Bouncer key for CrowdSec API.
        lapi_url(Optional) : str
            Base URL of CrowdSec API. Default is http://localhost:8080/ .
        """

        if api_key == "" and key_path == "" and cert_path == "":
            raise ValueError("You must provide an api_key or a key_path and cert_path")

        self.lapi_url = lapi_url
        self.session = create_session(
            api_key, insecure_skip_verify, key_path, cert_path, ca_cert_path, user_agent
        )

    def get_decisions_for(self, item):
        resp = self.session.get(f"{self.lapi_url}v1/decisions?ip={item}")
        resp.raise_for_status()
        return resp.json()

    def get_action_for(self, item):
        decisions = self.get_decisions_for(item)
        return max(decisions, key=lambda d: d["id"])["type"]


class BaseStreamClient(ABC):
    def __init__(
        self,
        api_key,
        lapi_url="http://localhost:8080/",
        interval=15,
        user_agent=f"python-bouncer/{__version__}",
        scopes=["ip", "range"],
        include_scenarios_containing=[],
        exclude_scenarios_containing=[],
        only_include_decisions_from=[],
        insecure_skip_verify=False,
        key_path="",
        cert_path="",
        ca_cert_path="",
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

        if api_key == "" and key_path == "" and cert_path == "":
            raise ValueError("You must provide an api_key or a key_path and cert_path")

        self.api_key = api_key
        self.scopes = scopes
        self.interval = int(interval)
        self.lapi_url = lapi_url
        self.user_agent = user_agent
        self.death_reason = None
        self.include_scenarios_containing = include_scenarios_containing
        self.exclude_scenarios_containing = exclude_scenarios_containing
        self.only_include_decisions_from = only_include_decisions_from

        self.session = create_session(
            api_key, insecure_skip_verify, key_path, cert_path, ca_cert_path, user_agent
        )
        self.__post_init__(**kwargs)

    def cycle(self, first_time):
        try:
            resp = self.session.get(
                url=f"{self.lapi_url}v1/decisions/stream",
                params={
                    "startup": first_time,
                    "scopes": ",".join(self.scopes),
                    "scenarios_containing": ",".join(self.include_scenarios_containing),
                    "scenarios_not_containing": ",".join(self.exclude_scenarios_containing),
                    "origins": ",".join(self.only_include_decisions_from),
                },
            )
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"pycrowdsec got error {e}")
            if first_time == "true":
                self.death_reason = e
                raise e
        self.process_response(resp.json())

    def run(self):
        self.cycle("true")  # So we catch errors on startup

        def _thread_cycle():
            while True:
                sleep(self.interval)
                self.cycle("false")

        self.t = threading.Thread(target=_thread_cycle, daemon=True)
        self.t.start()

    def is_running(self):
        return self.t.is_alive()

    @abstractmethod
    def process_response(self, response):
        pass

    @abstractmethod
    def __post_init__(self, **kwargs):
        pass


class StreamClient(BaseStreamClient):
    def __post_init__(self, **kwargs):
        if "redis_connection" in kwargs:
            self.cache = RedisCache(redis_connection=kwargs["redis_connection"])
        else:
            self.cache = Cache()

    def get_action_for(self, item):
        return self.cache.get(item)

    def get_current_decisions(self):
        return self.cache.get_all()

    def process_response(self, response):
        if response["new"] is None:
            response["new"] = []

        if response["deleted"] is None:
            response["deleted"] = []

        for decision in response["deleted"]:
            self.cache.delete(decision["value"])

        for decision in response["new"]:
            self.cache.insert(decision["value"], decision["type"])


class StreamDecisionClient(BaseStreamClient):
    def __post_init__(self, **kwargs):
        self.deleted_decisions = queue.SimpleQueue()
        self.new_decisions = queue.SimpleQueue()

    def get_new_decision(self):
        while not self.new_decisions.empty():
            yield self.new_decisions.get()

    def get_deleted_decision(self):
        while not self.deleted_decisions.empty():
            yield self.deleted_decisions.get()

    def process_response(self, response):
        if response["new"] is None:
            response["new"] = []

        if response["deleted"] is None:
            response["deleted"] = []

        for decision in response["deleted"]:
            self.deleted_decisions.put(decision)

        for decision in response["new"]:
            self.new_decisions.put(decision)
