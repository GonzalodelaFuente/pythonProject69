from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

from sqlalchemy import exc, Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

Base = declarative_base()

login_manager = LoginManager()

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#Comentario para comprobar si heroku actualiza

##CONFIGURE TABLES

class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False, unique=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)


    posts = relationship("BlogPost", back_populates='author')
    comments = relationship("Comment", back_populates='commenter')


class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author = relationship("User", back_populates='posts')
    comments = relationship("Comment")

class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    poster = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

    commenter = relationship("User", back_populates='comments')


db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def admin(user={}):
    try:
        return user.id == 1
    except:
        return False


@app.route('/')
def get_all_posts():
    print(f"In main page, registered = {current_user.is_active}")
    try:
        print(f"In main page, admin = {admin(current_user)}")
    except:
        pass
    posts = BlogPost.query.all()
    print(f"User = {load_user}")
    return render_template("index.html", all_posts=posts, registered=current_user.is_active, adminact=admin(current_user))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == "POST":
        form = request.form
        d = {}
        for item in form:
            if item not in ['csrf_token', 'submit']:
                print(item)
                if item == "password":
                    d[item] = generate_password_hash(form[item], method='pbkdf2:sha256', salt_length=8)
                else:
                    d[item] = form[item]
        user = User(**d)
        try:
            db.session.add(user)
            db.session.commit()
            user = db.session.query(User).filter(User.email == form['email']).first()
            login_user(user)
            print(admin(user))
            print(user.id)
            return redirect(url_for('get_all_posts', admin=admin(user)))
        except exc.IntegrityError:
            flash('An account with this name already exists')
            return redirect('/login')

    return render_template("register.html", form=form, registered=current_user.is_active)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        form = request.form
        user = db.session.query(User).filter(User.email == form['email']).first()
        if user:
            if check_password_hash(user.password, form['password']):
                login_user(user)
                print(f" in login user.id is {user.id}")
                print(f" in login admin is {admin(user)}")
                print(f" in login current_user.id is {current_user.id}")

                flash('Logged in successfully')
                print(load_user)
                return redirect(url_for('get_all_posts', admin=admin(user)))
            else:
                flash('Incorrect password')
                return redirect('/login')
        else:
            flash('Incorrect email')
            return redirect('/login')

    return render_template("login.html", form=form, registered=current_user.is_active)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    requested_comments = Comment.query.filter(Comment.post_id == post_id).all()
    for c in requested_comments:
        print(f"comment {c.id} = {c.comment}")
    form = CommentForm()

    print(current_user)

    if form.validate_on_submit():
        new_comment = Comment(comment=form.comment.data,
                              poster=current_user.id,
                              post_id=post_id)

        db.session.add(new_comment)
        db.session.commit()
        return render_template("post.html", form=form, post=requested_post, comments=requested_comments, registered=current_user.is_active, adminact=admin(current_user))
    return render_template("post.html", form=form, post=requested_post, comments=requested_comments, registered=current_user.is_active, adminact=admin(current_user))


@app.route("/about")
def about():
    return render_template("about.html", registered=current_user.is_active)


@app.route("/contact")
def contact():
    return render_template("contact.html", registered=current_user.is_active)


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%d %m, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, registered=current_user.is_active)


@app.route("/edit-post/<int:post_id>")
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, registered=current_user.is_active)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'), registered=current_user.is_active)




if __name__ == "__main__":
    app.run()
