from flask import Flask, request, abort
import re
import os

assert os.environ['FLAG']

app = Flask(__name__)

INDEX = open('index.html').read()

HALL_OF_SHAME = [
    '173.171.203.59',
    '2a02:6b8:b010:6026:84:201:185:197',
    '35.185.158.159'
]

@app.route('/')
def index():
    if os.environ.get("REMOTE_ADDR", '').lower() in HALL_OF_SHAME:
        abort(403)

    if 'f' in request.args:
        try:
            f = request.args['f']
            if re.search(r'proc|random|zero|stdout|stderr', f):
                abort(403)
            elif '\x00' in f:
                abort(404)
            return open(f).read(4096)
        except IOError:
            abort(404)
    else:
        return INDEX
