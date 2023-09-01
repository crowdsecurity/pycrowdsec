import pytest
from requests.exceptions import HTTPError

from pycrowdsec.client import StreamDecisionClient


def test_tls_mutual(crowdsec, certs_dir):
    """TLS with two-way bouncer/lapi authentication"""

    lapi_env = {
        "CACERT_FILE": "/etc/ssl/crowdsec/ca.crt",
        "LAPI_CERT_FILE": "/etc/ssl/crowdsec/lapi.crt",
        "LAPI_KEY_FILE": "/etc/ssl/crowdsec/lapi.key",
        "USE_TLS": "true",
        "LOCAL_API_URL": "https://localhost:8080",
        "LEVEL_DEBUG": "1",
    }

    certs = certs_dir(lapi_hostname="lapi")

    volumes = {
        certs: {"bind": "/etc/ssl/crowdsec", "mode": "ro"},
    }

    with crowdsec(environment=lapi_env, volumes=volumes) as cs:
        cs.wait_for_log("*CrowdSec Local API listening*")
        # TODO: wait_for_https
        cs.wait_for_http(8080, "/health", want_status=None)

        port = cs.probe.get_bound_port("8080")
        lapi_url = f"https://localhost:{port}/"

        bouncer = StreamDecisionClient(
            "",
            lapi_url,
            key_path=(certs / "bouncer.key").as_posix(),
            cert_path=(certs / "bouncer.crt").as_posix(),
            ca_cert_path=(certs / "ca.crt").as_posix(),
        )

        bouncer.cycle("true")
        cs.wait_for_log("*client OU ?agent-ou? is allowed vs required OU ?bouncer-ou?*")

        bouncer = StreamDecisionClient(
            "",
            lapi_url,
            key_path=(certs / "agent.key").as_posix(),
            cert_path=(certs / "agent.crt").as_posix(),
            ca_cert_path=(certs / "ca.crt").as_posix(),
        )

        with pytest.raises(HTTPError, match="403"):
            bouncer.cycle("true")

        cs.wait_for_log(
            "*client certificate OU (?agent-ou?) doesn't match expected OU (?bouncer-ou?)*"
        )
