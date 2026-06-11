"""Flask REST API route definitions."""

from flask import Blueprint, jsonify

api = Blueprint('api', __name__, url_prefix='/api/v3')

@api.route('/status')
def status():
    return jsonify({'status': 'ok'})
