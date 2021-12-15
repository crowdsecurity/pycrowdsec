<p align=center>
<img src="https://raw.githubusercontent.com/crowdsecurity/pycrowdsec/main/assets/pycrowdsec.jpg" width="280" height="300" >
</p>

<p align="center">
<a href="https://gitter.im/crowdsec-project/community"><img src="https://badges.gitter.im/gitterHQ/gitter.png"></a>
<img src="https://img.shields.io/badge/License-MIT-blue.svg">
</p>

# PyCrowdSec

[CrowdSec](https://github.com/crowdsecurity/crowdsec) is a FOSS tool which parses logs and detects attacks. PyCrowdSec enables integration of CrowdSec with python projects. It is easy to setup and boosts the security by leveraging CrowdSec's attack detection capabilities.

PyCrowdSec contains a python client library for CrowdSec, as well as middlewares for django and flask integrations.

## Installation:

```bash
pip install pycrowdsec
```

You'll also need an instance of CrowdSec running, see installation instructions [here](https://docs.crowdsec.net/Crowdsec/v1/getting_started/installation/)

## Client library:

### StreamClient

This client polls CrowdSec LAPI and keeps track of active decisions.
In the below example assume that there's a ban decisions for IP "77.88.99.66" and captcha decision for country "CN".

**Basic Usage:**

```python
from pycrowdsec.client import StreamClient
client = StreamClient(
    api_key=<CROWDSEC_API_KEY>,
)

client.run() # This starts polling the API

assert client.get_current_decisions() == {
    "77.88.99.66": "ban"
    "CN": "captcha"
}

assert client.get_action_for("77.88.99.66") == "ban"
assert client.get_action_for("CN") == "captcha"
```

The `CROWDSEC_API_KEY` can be obtained by running 
```bash
sudo cscli bouncers add python_bouncer
```

The `StreamClient`'s constructor also accepts the following optional parameters for more advanced configurations.

**lapi_url** : str
    Base URL of CrowdSec API. Default is http://localhost:8080/ .

**interval** : int
    Query the CrowdSec API every "interval" second

**user_agent** : str
    User agent to use while calling the API.

**scopes** : List[str]
    List of decision scopes which shall be fetched. Default is ["ip", "range"]

### QueryClient

This client will query CrowdSec LAPI to check whether the requested item has any decisions against it.
In the below example assume that there's a ban decisions for IP "77.88.99.66" and captcha decision for country "CN".


**Basic Usage:**

```python

from pycrowdsec.client import StreamClient
client = StreamClient(
    api_key=<CROWDSEC_API_KEY>,
)

client.run() # This starts polling the API

assert client.get_action_for("77.88.99.66") == "ban"
assert client.get_action_for("CN") == "captcha"

```

The `QueryClient`'s constructor also accepts the following optional parameters for more advanced configurations.

**lapi_url** : str
    Base URL of CrowdSec API. Default is http://localhost:8080/ .

**user_agent** : str
    User agent to use while calling the API.


## Flask Integration:

See `./examples/flask` for more detailed example (includes captcha remediation too).

A minimal flask app with PyCrowdSec protection would look like:
```python
from flask import Flask

from pycrowdsec.client import StreamClient
from pycrowdsec.flask import get_crowdsec_middleware

client = StreamClient(api_key=<CROWDSEC_API_KEY>)
app = Flask(__name__)
app.before_request(
    get_crowdsec_middleware(actions, c.cache, exclude_views=["ban_page"]
)

actions = {
    "ban": lambda: redirect(url_for("ban_page")),
}

@app.route("/ban")
def ban_page():
    return abort(403)

@app.route("/")
def index():
    return "Hello"

if __name__ = "__main__":
    app.run(host="0.0.0.0")
```

## Django Integration:

See `./examples/django` for more detailed example (includes captcha remediation too).

After installing `pycrowdsec`, in your `settings.py` add the following line in the `MIDDLEWARE` list

```python
MIDDLEWARE = [
    .........
    "pycrowdsec.django.crowdsec_middleware",
    .........
]
```

Next add define the following variables required for `pycrowdsec` to function.

```python
PYCROWDSEC_LAPI_KEY = <YOUR_LAPI_KEY>
PYCROWDSEC_ACTIONS = {
    "ban": lambda request: redirect(reverse("ban_view")),
}
# IMPORTANT: If any action is doing a redirect to some view, always exclude it for pycrowdsec. Otherwise the middleware will trigger the redirect on the action view too.
PYCROWDSEC_EXCLUDE_VIEWS = {"ban_view"}
```


You'll also need to register a view with name `ban_view`. In this example all the banned IPs would be redirected to the `ban_view`

For more advanced configurations, you can specify the following variables in your `settings.py`

**PYCROWDSEC_POLL_INTERVAL**  int : Query the CrowdSec API every `PYCROWDSEC_POLL_INTERVAL` seconds.

**PYCROWDSEC_LAPI_URL** str: Base URL of CrowdSec API.

**PYCROWDSEC_ACTIONS** Dict[str, Callable]: Action to be taken when some request matches CrowdSec's decision.

**PYCROWDSEC_REQUEST_TRANSFORMERS** List[Callable]: Obtains value from Django Request object, this value is used to match the request with CrowdSec's decisions. By default it contains only one transformer which obtains IP from the request.
