from flask import Flask, render_template, redirect, request
from data import db_session
from data.users import User
from data.films import Film
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'

global USER
USER = ''

def main():
    db_session.global_init("db/kinoteatr.db")
    db_sess = db_session.create_session()
    app.run(port=8080, host='127.0.0.1')

def buy_ticket(Login, card_num, seat, film_name):
    db_sess = db_session.create_session()
    film = db_sess.query(Film).filter(Film.name == film_name).first()
    film_buys = film.buys
    film.buys = str(film_buys) + str(seat) + ';'
    db_sess.commit()

def make_film(Name, Description, Cost, Time, Buys, Img):
    film = Film()
    film.name = Name
    film.description = Description
    film.cost = Cost
    film.time = Time
    film.buys = Buys
    film.img = Img
    film.img_1 = Img
    db_sess = db_session.create_session()
    db_sess.add(film)
    db_sess.commit()

def delete_film(Name):
    db_sess = db_session.create_session()
    film = db_sess.query(Film).filter(Film.name == Name).first()
    db_sess.delete(film)
    db_sess.commit()

def create_hash(password):
    password_bytes = password.encode()
    salt = bcrypt.gensalt(14)
    password_hash_bytes = bcrypt.hashpw(password_bytes, salt)
    password_hash_str = password_hash_bytes.decode()            
    return password_hash_str

def if_password(password, hash_from_database):
    password_bytes = password.encode()
    hash_bytes = hash_from_database.encode()
    does_match = bcrypt.checkpw(password_bytes, hash_bytes)
    return does_match

def make_user(Name, Login, Password):
    if Name != '' and Login != '' and Password != '':
        if "admin" not in Name and "admin" not in Login:
            db_sess = db_session.create_session()
            k = 0
            usercount = len(db_sess.query(User).all())
            for x in range(1, usercount + 1):
                bdName = db_sess.query(User).filter(User.id == x).one().name
                if Name == bdName:
                    k = 1
                    return '/error/Имя уже у кого-то есть, просим вас его заменить'
                bdLogin = db_sess.query(User).filter(User.id == x).one().login
                if Login == bdLogin:
                    k = 1
                    return '/error/Логин уже у кого-то есть, просим вас его заменить'
            if k == 0:
                user = User()
                user.name = Name
                user.login = Login
                user.hashed_password = create_hash(Password)
                db_sess = db_session.create_session()
                db_sess.add(user)
                db_sess.commit()
                return 'SIGNUP'
        else:
            return 'NO ADMIN'
    else:
        return 'NO PARAM'

def check_user(Logna, password):
    k = 0
    db_sess = db_session.create_session()
    usercount = len(db_sess.query(User).all())
    if Logna == '' or password == '':
        return redirect('/error/Пароль и логин не должны быть пустыми')
    else:
        for x in range(1, usercount + 1):
            if "admin" in Logna:
                pass_from_db = db_sess.query(User).filter(User.id == x).one().hashed_password
                okpassword = if_password(password, pass_from_db)
                if okpassword:
                    return 'ADMIN'
            else:
                login = db_sess.query(User).filter(User.id == x).one().login
                if Logna == login:
                    pass_from_db = db_sess.query(User).filter(User.id == x).one().hashed_password
                    okpassword = if_password(password, pass_from_db)
                    if okpassword:
                        return 'LOGIN'
        if k == 0:
            return 'NO'

@app.route('/')
def index():
    global USER
    film = {'film': []}
    db_sess = db_session.create_session()
    filmcount = len(db_sess.query(Film).all())
    for i in range(1, filmcount + 1):
        film['film'].append({})
        db_sess = db_session.create_session()
        name = db_sess.query(Film).filter(Film.id == i).one().name
        film['film'][i - 1]['film_name'] = name
        des = db_sess.query(Film).filter(Film.id == i).one().description
        film['film'][i - 1]['film_description'] = des
        time = db_sess.query(Film).filter(Film.id == i).one().time
        film['film'][i - 1]['film_time'] = time
        img = db_sess.query(Film).filter(Film.id == i).one().img
        film['film'][i - 1]['film_img'] = img
        img_1 = db_sess.query(Film).filter(Film.id == i).one().img_1
        film['film'][i - 1]['film_img_1'] = img_1
    print(USER)
    return render_template('index.html', film=film)

@app.route('/film/<film>')
def film(film=''):
    global USER
    db_sess = db_session.create_session()
    buys = db_sess.query(Film).filter(Film.name == film).one().buys
    all_buys = buys.split(';')
    film_param = {}
    db_sess = db_session.create_session()
    film_param['film_title'] = film
    film_param['film_buys'] = all_buys
    film_param['film_description'] = db_sess.query(Film).filter(Film.name == film).one().description
    film_param['film_cost'] = db_sess.query(Film).filter(Film.name == film).one().cost
    film_param['film_img'] = db_sess.query(Film).filter(Film.name == film).one().img_1
    return render_template('film.html', **film_param)

@app.route('/buy/<film>/<place>', methods=['GET', 'POST'])
def buy(film='', place=0):
    global USER
    if request.method == "GET":
        db_sess = db_session.create_session()
        buys = db_sess.query(Film).filter(Film.name == film).one().buys
        all_buys = buys.split(';')
        if place not in all_buys:
            place_param = {}
            place_param['film'] = film
            place_param['place'] = (int(place) - 1) % 12 + 1
            place_param['row'] = (int(place) - 1) // 12 + 1
            return render_template('buy.html', **place_param)
        else:
            return redirect('/error/К сожалению, место уже куплено')
    elif request.method == "POST":
        Log = request.form['login']
        Card = request.form['card']
        buy_ticket(Log, Card, place, film)
        return redirect('/thanks/Спасибо за покупку билета')

@app.route('/login', methods=["GET", "POST"])
def login():
    global USER
    if request.method == "GET":
        return render_template('login.html')
    elif request.method == "POST":
        Log = request.form['login']
        Pass = request.form['password']
        if check_user(Log, Pass) == 'ADMIN':
            USER = Log
            return redirect('/admin_main')
        elif check_user(Log, Pass) == 'LOGIN':
            USER = Log
            return redirect('/')
        else:
            USER = Log
            return redirect('/error/Неверный логин или пароль')

@app.route('/signup', methods=["GET", "POST"])
def signup():
    global USER
    if request.method == "GET":
        return render_template('signup.html')
    elif request.method == "POST":
        Name = request.form['name']
        Log = request.form['login']
        Pass = request.form['password']
        make_us = make_user(Name, Log, Pass)
        if make_us == 'SIGNUP':
            USER = Log
            return redirect('/')
        elif make_us == 'NO PARAM':
            USER = Log
            return redirect('/error/Заполните все поля')

@app.route('/admin_main')
def admin_main():
    global USER
    film = {'film': []}
    db_sess = db_session.create_session()
    filmcount = len(db_sess.query(Film).all())
    for i in range(1, filmcount + 1):
        film['film'].append({})
        db_sess = db_session.create_session()
        name = db_sess.query(Film).filter(Film.id == i).one().name
        film['film'][i - 1]['film_name'] = name
        des = db_sess.query(Film).filter(Film.id == i).one().description
        film['film'][i - 1]['film_description'] = des
        time = db_sess.query(Film).filter(Film.id == i).one().time
        film['film'][i - 1]['film_time'] = time
        img = db_sess.query(Film).filter(Film.id == i).one().img
        film['film'][i - 1]['film_img'] = img
    return render_template('admin_main.html', film=film)

@app.route('/create_film', methods=['GET', 'POST'])
def create_film():
    if request.method == "GET":
        return render_template('create_film.html')
    elif request.method == "POST":
        Name = request.form['name']
        Cost = request.form['cost']
        Time = request.form['time']
        Description = request.form['des']
        Buys = ''
        Img = request.form['img']
        Img_1 = request.form['img_1']
        if Name != '' and Description != '' and Cost != '' and Time != '' and Img != '' and Img_1 != '':
            make_film(Name, Description, Cost, Time, Img, Img_1)
            return redirect('/thanks/Фильм добавлен')
        else:
            return redirect('/error/Все поля должны быть заполнены!')

@app.route('/delete_film/<film>', methods=['GET', 'POST'])
def del_film(film=''):
    if request.method == "GET":
        return render_template('delete_film.html', film=film)
    elif request.method == "POST":
        print(film)
        delete_film(film)
        return thanks('/thanks/Фильм удален')

@app.route('/error/<error>')
def error(error=''):
    return render_template('error.html', error=error)

@app.route('/thanks/<thanks>')
def thank(thanks=''):
    return render_template('thanks.html', thanks=thanks)

if __name__ == '__main__':
    main()
