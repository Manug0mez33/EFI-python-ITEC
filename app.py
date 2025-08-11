from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def login():
    return render_template("login.html")

@app.route('/index')
def index():
    return render_template("index.html")

@app.route('/post')
def post():
    return render_template("post.html")

@app.route('/comentario')
def comentario():
    return render_template("comentario.html")

@app.route('/categoria')
def categoria():
    return render_template("categoria.html")

if __name__ == '__main__':
    app.run(debug=True)