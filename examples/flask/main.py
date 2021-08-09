from pycrowdsec.client import StreamClient
from flask import Flask
from flask import request


c = StreamClient(
    lapi_url="http://localhost:8080/",
    api_key="1ae6f423ec73130e87773f2c0c2477fe",
    interval=5,
    scopes="",
)
c.run()

app = Flask(__name__)

@app.before_request
def check_in_ban_list():
    print(request.remote_addr)
    if request.remote_addr in c.action_by_item:
        return "<h1> You are banned </h1>"



@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

if __name__ == "__main__":
    app.run(host='0.0.0.0')