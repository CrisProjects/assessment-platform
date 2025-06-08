from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello from Render! App is working correctly.'

@app.route('/health')
def health():
    return {'status': 'healthy', 'message': 'Minimal Flask app is running'}

if __name__ == '__main__':
    app.run(debug=True)
