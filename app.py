from app_factory import create_app
from flask import render_template

app = create_app()

# ---------- ERROR HANDLERS ----------

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)