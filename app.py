import json
from io import BytesIO
from flask import Flask, render_template, request, send_file
from analyzer import analyze_email

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    raw_email = ""

    if request.method == "POST":
        raw_email = request.form.get("raw_email", "").strip()
        uploaded = request.files.get("email_file")

        if uploaded and uploaded.filename:
            if not uploaded.filename.lower().endswith(".eml"):
                error = "Please upload an .eml file. You can also paste raw email headers and content."
            else:
                try:
                    raw_email = uploaded.read().decode("utf-8", errors="replace")
                except Exception:
                    error = "Could not read the uploaded file."

        if not error:
            if not raw_email:
                error = "Paste an email or choose an .eml file first."
            else:
                try:
                    result = analyze_email(raw_email)
                    # Keep the analyzed email in the text box after submission.
                except Exception as exc:
                    error = f"Could not analyze this input: {exc}"

    return render_template("index.html", result=result, error=error, raw_email=raw_email)


@app.post("/report")
def report():
    raw_email = request.form.get("raw_email", "")
    if not raw_email.strip():
        return "No email content supplied.", 400
    result = analyze_email(raw_email)
    payload = json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")
    return send_file(
        BytesIO(payload),
        mimetype="application/json",
        as_attachment=True,
        download_name="phishguard-investigation-report.json"
    )


if __name__ == "__main__":
    # Local-only by default; do not expose this unreviewed tool to the internet.
    app.run(host="127.0.0.1", port=5000, debug=False)
