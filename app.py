from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def landing():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/sign-up')
def sign():
    return render_template('sign-up.html')

@app.route('/login')
def login():
    return render_template('log-in.html')

if __name__ == '__main__':
    app.run(debug=True)
