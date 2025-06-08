from flask import Flask, render_template

app = Flask(__name__)

# ¡ATENCIÓN!
# Este archivo solo existe para evitar que Render use el app.py de la raíz.
# El backend Flask real está en /backend/app.py
# No ejecutar ni modificar este archivo para producción.

@app.route('/')
def index():
    return render_template('index.html')

raise RuntimeError("Este archivo app.py es solo un placeholder. Usa /backend/app.py para el backend Flask.")
