# Udacity Nanodegree Project 3: Multi User Blog

import os
import re
import random
import hashlib
import hmac
from string import letters
import time

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'iamasecret'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# parent blog handler class
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, world!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    author = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    likes = db.IntegerProperty()
    likers = db.StringListProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts, user = self.user)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = str(self.user.name), likes = 0)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

# TODO
class Edit(BlogHandler):
    def get(self, post_id):
        # UNSURE
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            error = "You must be logged in to edit a post"
            self.render("permalink.html", post = post, error = error)
        elif self.user.name != post.author:
            # popup error message
            # return to /blog
            error = "You do not have permission to edit this post"
            self.render("permalink.html", post = post, error = error)
            # self.redirect('/blog')
        else:
            self.render("edit.html", post = post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user.name != post.author:
            # popup error message
            # return to /blog
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))

class DeletePost(BlogHandler):
    def get(self, post_id):
        # UNSURE
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            error = "You must be logged in to edit or delete a post"
            self.render("permalink.html", post = post, error = error)
        elif self.user.name != post.author:
            # popup error message
            # return to /blog
            error = "You do not have permission to edit or delete this post"
            self.render("permalink.html", post = post, error = error)
            # self.redirect('/blog')
        else:
            self.render("delete-post.html", post = post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user.name != post.author:
            # popup error message
            # return to /blog
            self.redirect('/blog')

        answer = self.request.get('answer')

        if answer == "yes":
            # DELETE POST FROM DATASTORE AND REDIRECT TO /blog
            post.delete()
            self.redirect('/blog')
        else:
            # redirect back to post page
            self.redirect('/blog/%s' % str(post.key().id()))

class LikePost(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            error = "You must be logged in to like a post"
            self.render("permalink.html", post = post, error = error)
        elif self.user.name == post.author:
            # popup error message
            # return to /blog
            error = "You cannot like your own post"
            self.render("permalink.html", post = post, error = error)
            # self.redirect('/blog')
        else:

            if self.user.name not in post.likers:
                post.likes = post.likes + 1
                post.likers.append(self.user.name)

                if self.user.name != post.author:
                    post.put()
                    time.sleep(0.1)
                    self.redirect('/blog')
            else:
                self.redirect('/blog')

class UnlikePost(BlogHandler):
    # TODO
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            error = "You must be logged in to unlike a post"
            self.render("permalink.html", post = post, error = error)
        elif self.user.name == post.author:
            error = "You cannot unlike your own post"
            self.render("permalink.html", post = post, error = error)
        elif self.user.name in post.likers:
            # remove from likers
            post.likers.remove(self.user.name)
            post.likes = post.likes - 1
            post.put()
            time.sleep(0.1)
            self.redirect('/blog')

#create a Comment class
# class Comment(db.Model):
#     comment = db.TextProperty(required = True)
#     commentAuthor = db.StringProperty(required = True)
#     commentID = db.IntegerProperty(required = True)
#     created = db.DateTimeProperty(auto_now_add = True)

# class NewComment(BlogHandler):
#     def get(self, post_id):
#         key = db.Key.from_path('Post', int(post_id), parent=blog_key())
#         post = db.get(key)

#         if not self.user:
#             error = "you need to be logged in to comment on posts"
#             self.render("login.html", error=error)
#         else:
#             self.render("new-comment.html", p=post)

#     def post(self, post_id):
#         key = db.Key.from_path('Post', int(post_id), parent=blog_key())
#         post = db.get(key)

#         comment_og = self.request.get('comment')
#         comment = comment_og.replace('\n', '<br>')
#         commentAuthor = self.user.name
#         commentID = int(p.key().id())

#         if self.user:
#             if commentAuthor and comment and commentID:
#                 c = Comment(parent = blog_key(), comment=comment,
#                             commentAuthor=commentAuthor, commentID = commentID)
#                 c.put()
#                 self.redirect("/blog")
#             else:
#                 error = "You have to enter text in the comment field!"
#                 return self.render("newcomment.html", p=post, error=error)


    # TODO
    # check user is not trying to comment on their own post

# regular expressions/functions to check for valid user names/passwords/emails on signup
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That is not a valid username"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That isn't a valid password"
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords don't match"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That is not a valid email"
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        # TODO - dunno if this is right
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/signup')

# ('/blog/newcomment/([0-9]+)', NewComment),
# ('/blog/like/([0-9]+)', LikePost),
# ('/blog/unlike/([0-9]+)', UnlikePost),

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/edit/([0-9]+)', Edit),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/like/([0-9]+)', LikePost),
                               ('/blog/unlike/([0-9]+)', UnlikePost),
                               ],
                              debug=True)
