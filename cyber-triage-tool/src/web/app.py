import sys
print(f"Running Python from: {sys.executable}")
print(f"Module search path: {sys.path}")

from flask import Flask, render_template, abort, jsonify
from flask import Flask, render_template, abort, jsonify
from pathlib import Path
import json
from bootstrap_flask import Bootstrap

def create_app():
    app = Flask(__name__)
    Bootstrap(app)

    CASES_DIR = Path(__file__).parent.parent.parent / "data/cases"

    @app.route("/")
    def index():
        try:
            cases = [d.name for d in CASES_DIR.iterdir() if d.is_dir()]
        except FileNotFoundError:
            cases = []
        return render_template("index.html", cases=cases)

    @app.route("/report/<case_id>")
    def report(case_id):
        report_path = CASES_DIR / case_id / "report.json"
        if not report_path.exists():
            abort(404, description="Report not found")
        
        with open(report_path) as f:
            summary = json.load(f).get("summary", {})
            
        return render_template("report.html", summary=summary)

    @app.route("/api/report/<case_id>")
    def report_data(case_id):
        report_path = CASES_DIR / case_id / "report.json"
        if not report_path.exists():
            abort(404)
            
        with open(report_path) as f:
            data = json.load(f)
            
        return jsonify(data)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=8000)