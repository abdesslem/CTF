from flask import Flask, render_template, redirect, url_for, flash, session, abort, request
from werkzeug.security import generate_password_hash, check_password_hash


@app.route('/')
def index():
    if not current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('login'))
    challenges = Challenges.query.all()
    query = db.session.query(Challenges.category.distinct().label("category"))
    categories = [row.category for row in query.all()]
    ranking = rank(current_user.username)
    #tasks = Challenges.query.group_by(Challenges.category).all()
    return render_template('index.html', challenges=challenges, categories=categories, ranking=ranking)

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
	user = User(username=form.login.data,
                       email=form.email.data,
		       password=form.password.data,
		       school=form.school.data)
	db.session.add(user)
	db.session.commit()
	flash('Thank you for registration')
	return render_template('index.html')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
	user = User.query.filter_by(username=form.login.data).first()
	if user is None or not user.verify_password(form.password.data):
	    flash('Invalid username or password')
	    return redirect(url_for('login'))
        login_user(user)
        flash('Logged in successfully.')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Logout the current user."""
    logout_user()
    return redirect(url_for('index'))

@app.route('/rules')
@login_required
def rules():
    return render_template('rules.html')

@app.route('/scoreboard')
@login_required
def scoreboard():
    users = User.query.order_by(desc(User.score)).all()
    return render_template('scoreboard.html', users=users)

@app.route('/challenges/<challenge_name>',methods=["GET","POST"])
@login_required
def challenges(challenge_name):
    form = FlagForm()
    challenge = Challenges.query.filter_by(name=challenge_name).first()
    if form.validate_on_submit() and challenge.flag == form.flag.data :
        flash('Good Job Valid Flag')
        return redirect(url_for('index'))
    elif form.validate_on_submit() and challenge.flag != form.flag.data :
        flash('Wrong Flag')
        return render_template('challenges.html',form=form, challenge=challenge )
    return render_template('challenges.html',form=form, challenge=challenge )

