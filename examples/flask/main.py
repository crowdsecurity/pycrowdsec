from pycrowdsec.client import StreamClient
from flask import Flask
from flask import request, abort

c = StreamClient(
    lapi_url="http://localhost:8080/",
    api_key="",  # your crowdsec LAPI bouncer key goes here
    interval=5,
    scopes="",
)
c.run()

app = Flask(__name__)


@app.before_request
def check_in_ban_list():
    action = c.cache.get(request.remote_addr)
    if not action:
        return
    if action == "ban":
        return "You have been banned"

    if action == "captcha":
        return "You have captcha"


@app.route("/")
def hello_world():
    abort(403)
    # return "<p>Hello, World!</p>"


if __name__ == "__main__":
    app.run(host="0.0.0.0")
