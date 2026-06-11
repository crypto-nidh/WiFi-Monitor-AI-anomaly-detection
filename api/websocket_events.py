"""SocketIO event handlers."""

from flask_socketio import emit


def setup_socketio(socketio):
    @socketio.on('connect')
    def on_connect():
        emit('connected', {'message': 'SocketIO connected'})
