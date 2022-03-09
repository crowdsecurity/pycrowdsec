import os

import requests
from expiringdict import ExpiringDict
from flask import Flask, abort, redirect, render_template, request, session, url_for

from pycrowdsec.client import StreamClient
from pycrowdsec.flask import get_crowdsec_middleware

c = StreamClient(
    lapi_url="http://localhost:8080/",
    api_key=os.environ.get("CROWDSEC_LAPI_KEY"),  # your crowdsec LAPI bouncer key goes here
    interval=5,
)
c.run()

app = Flask(__name__)
app.secret_key = "SET_SECRET_KEY"

# In Production env use a "real" cache backend for this. Otherwise
# different app instances would end up having different "valid_captcha_keys".
valid_captcha_keys = ExpiringDict(max_len=1000, max_age_seconds=30)


def validate_captcha_resp(g_recaptcha_response):
    resp = requests.post(
        url="https://www.google.com/recaptcha/api/siteverify",
        data={
            "secret": os.environ.get("GOOGLE_RECAPTCHA_PRIVATE_KEY"),
            "response": g_recaptcha_response,
        },
    ).json()
    return resp["success"]


actions = {
    "ban": lambda: redirect(url_for("ban_page")),
    "captcha": lambda: redirect(url_for("captcha_page"))
    if session.get("captcha_resp") not in valid_captcha_keys
    else None,
}

app.before_request(
    get_crowdsec_middleware(actions, c.cache, exclude_views=("captcha_page", "ban_page"))
)


@app.route("/captcha", methods=["GET", "POST"])
def captcha_page():
    if request.method == "GET":
        return render_template(
            "captcha_page.html", public_key=os.environ.get("GOOGLE_RECAPTCHA_SITE_KEY")
        )
    elif request.method == "POST":
        captcha_resp = request.form.get("g-recaptcha-response")
        if not captcha_resp:
            return redirect(url_for("captcha_page"))

        is_valid = validate_captcha_resp(captcha_resp)
        if not is_valid:
            return redirect(url_for("captcha_page"))

        session["captcha_resp"] = captcha_resp
        valid_captcha_keys[captcha_resp] = None
        return redirect(url_for("index"))


@app.route("/")
def index():
    return "Hello"


@app.route("/ban")
def ban_page():
    return abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
