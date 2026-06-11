from flask import Flask
from flask_socketio import SocketIO

app = Flask(__name__)
app.config.from_object('config')
socketio = SocketIO(app)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
