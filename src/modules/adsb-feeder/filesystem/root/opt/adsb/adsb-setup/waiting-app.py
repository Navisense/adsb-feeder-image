import json
from flask import Flask, Response, render_template
import re
import os
from sys import argv
import time

app = Flask(__name__)
logfile = "/run/porttracker-sdr-feeder.log"
title = "Restarting the ADS-B Feeder System"
theme = "auto"


# We need to fake having get_conf so that the waiting.html can be used both by
# this and the main app.
@app.context_processor
def utility_processor():
    return {"get_conf": lambda _: theme}


@app.route("/stream-log")
def stream_log():
    def tail():
        with open(logfile, "r") as file:
            ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
            tmp = file.read()[-16 * 1024:]
            # discard anything but the last 16 kB
            while True:
                tmp += file.read(16 * 1024)
                if tmp and tmp.find("\n") != -1:
                    block, tmp = tmp.rsplit("\n", 1)
                    block = ansi_escape.sub("", block)
                    lines = block.split("\n")
                    data = "".join(["data: " + line + "\n" for line in lines])
                    yield data + "\n\n"
                else:
                    time.sleep(0.2)

    return Response(tail(), mimetype="text/event-stream")


@app.route("/restart")
def restarting():
    return "stream-log"


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def waiting(path):
    return render_template("waiting.html", title=title)


if __name__ == "__main__":
    port = 80
    if len(argv) >= 2:
        port = int(argv[1])
    if len(argv) >= 3:
        logfile = argv[2]
    if len(argv) >= 4:
        title = argv[3] + " ADS-B Feeder System"

    print(
        f'Starting waiting-app.py on port {port} with title "{title}" '
        f"streaming logfile {logfile}")
    if os.path.exists("/etc/adsb/config.json"):
        with open("/etc/adsb/config.json") as f:
            config = json.load(f)
        theme = config.get("_ASDBIM_CSS_THEME", "auto")
    app.run(host="0.0.0.0", port=port)
