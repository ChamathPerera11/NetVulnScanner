import re

from flask import Flask, render_template, request

from scanner import scan_target
from vulnerability import check_vulnerability
from database import create_database, save_result, get_results


app = Flask(__name__)

create_database()

TARGET_PATTERN = re.compile(r"^[A-Za-z0-9.:_-]{1,255}$")


@app.route("/")
def index():

    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    target = request.form.get("target", "").strip()

    if not TARGET_PATTERN.match(target):
        return render_template(
            "index.html",
            error="Enter a valid IP address or hostname (letters, numbers, dots, colons, hyphens only)."
        ), 400

    try:
        scan_results = scan_target(target)
    except Exception as exc:
        return render_template(
            "index.html",
            error=f"Scan failed: {exc}"
        ), 500

    results = []

    for result in scan_results:

        vulnerability = check_vulnerability(result)

        save_result(
            result,
            vulnerability
        )

        results.append({**result, **vulnerability})

    return render_template(
        "results.html",
        results=results
    )


@app.route("/history")
def history():

    results = get_results()

    return render_template(
        "results.html",
        results=results
    )


if __name__ == "__main__":

    import os
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")