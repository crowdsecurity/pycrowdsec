import os
import requests
from expiringdict import ExpiringDict

from flask import Flask
from flask import request, render_template, session, redirect, url_for, abort
from pycrowdsec.client import StreamClient
from pycrowdsec.flask import get_crowdsec_middleware

c = StreamClient(
    lapi_url="http://localhost:8080/",
    api_key=os.environ.get("CROWDSEC_LAPI_KEY"),  # your crowdsec LAPI bouncer key goes here
    interval=5,
    scopes="",
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
    "ban": lambda destination_view: redirect(url_for("ban")) if destination_view != "ban" else None,
    "captcha": lambda destination_view: redirect(url_for("captcha_page"))
    if destination_view != "captcha_page" and not session.get("captcha_resp") in valid_captcha_keys
    else None,
}

app.before_request(get_crowdsec_middleware(actions, c.cache))


@app.route("/captcha", methods=["GET", "POST"])
def captcha_page():
    if request.method == "GET":
        return render_template(
            "./captcha_page.html", public_key=os.environ.get("GOOGLE_RECAPTCHA_SITE_KEY")
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
def ban():
    return abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
