from flask import Flask, render_template, request

from scanner import scan_target
from vulnerability import check_vulnerability
from database import create_database, save_result, get_results


app = Flask(__name__)

create_database()


@app.route("/")
def index():

    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    target = request.form["target"]

    results = scan_target(target)

    for result in results:

        vulnerability = check_vulnerability(result)

        save_result(
            result,
            vulnerability
        )

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

    app.run(
        debug=True
    )