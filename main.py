from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor,CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length
from wtforms import StringField, TextAreaField, PasswordField, SubmitField
from wtforms.fields.html5 import EmailField
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
Base = declarative_base()
class BlogPost(db.Model,Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author = relationship("User", back_populates="posts")
    author_id = Column(Integer, ForeignKey('all_users.id'))

    comments = relationship("Comment", back_populates="blog")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

class Comment(db.Model,Base):
    __tablename__ = "blog_comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)

    comment_user_id = Column(Integer, ForeignKey('all_users.id'))
    comment_user = relationship("User", back_populates="comments")

    blog_id = Column(Integer, ForeignKey('blog_posts.id'))
    blog = relationship("BlogPost", back_populates="comments")


class User(UserMixin,db.Model,Base):
    __tablename__ = "all_users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    posts = relationship('BlogPost',back_populates="author")

    comments = relationship('Comment',back_populates="comment_user")

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# form class
class RegisterForm(FlaskForm):
    name = StringField('Your Name', validators=[InputRequired()])
    email = EmailField('Your Email',validators=[InputRequired()])
    password = PasswordField("Password",validators=[InputRequired()])
    submit_button = SubmitField('Register')

class LoginForm(FlaskForm):
    email = EmailField('Your Email',validators=[InputRequired()])
    password = PasswordField("Password",validators=[InputRequired()])
    submit_button = SubmitField('Login')

class CommentForm(FlaskForm):
    body = CKEditorField('Body')
# ------ Admin-only decorator ---------------#
from functools import wraps
from flask import g, request

@app.before_request
def before_request():
    g.user = current_user

@app.errorhandler(404)
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None or g.user.id!=1 :
            return render_template('403.html'),403
        return f(*args, **kwargs)
    return decorated_function



@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register',methods=['POST','GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # form.name.data
        new_user = User(name=form.name.data, email=form.email.data, password=generate_password_hash(form.password.data, method='pbkdf2:sha256',salt_length=8))
        if User.query.filter_by(email=form.email.data).first():
            flash("You have registered before, please login!")
            return redirect(url_for('login'))
        else:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
    return render_template("register.html",form=form)


@app.route('/login',methods=['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_found = User.query.filter_by(email=form.email.data).first()
        if not user_found:
            flash("No account found, please register instead!")
            return redirect(url_for('register'))
        else:
            if check_password_hash(user_found.password, form.password.data):
                login_user(user_found)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Wrong password, please try again!")
    return render_template("login.html",form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))



@app.route("/post/<int:post_id>",methods=['POST','GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    # comment input
    form = CommentForm()
    if form.validate_on_submit():
        print("ok")
        new_comment = Comment(comment_user_id=g.user.id, comment=form.body.data, blog_id=post_id)
        db.session.add(new_comment)
        db.session.commit()
    # show all comment
    comments = Comment.query.all()
    return render_template("post.html", form=form, post=requested_post, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=['POST','GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        print(g.user.name)
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id = current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>",methods=['POST','GET'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000,debug=True)
