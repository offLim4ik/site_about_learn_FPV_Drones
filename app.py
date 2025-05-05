from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/main')
def main_page():
    return render_template('main.html')

@app.route('/contacts')
def contacts():
    pass

@app.route('/about')
def about():
    pass

if __name__ == '__main__':
    app.run(debug=True)