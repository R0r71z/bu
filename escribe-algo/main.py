import os
import jinja2
from threading import Timer
from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates' )
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)
import webapp2
import re
import hashlib
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def filter(s):
    s = s.replace("<", "&lt").replace(">", "&gt")
    return s.replace("&ltbr&gt", "<br>")

def valid_username(username):
    if USER_RE.match(username):
        return True
    return False
def valid_password(password):
    if PASS_RE.match(password):
        return True
    return False
def valid_email(email):
    if email== "":
        return None
    if EMAIL_RE.match(email):
        return True
    return False

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a,**kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class UsersDB(db.Model):
    username = db.StringProperty(required = True)
    password = db.TextProperty(required = True)
    registered = db.DateTimeProperty(auto_now_add = True)

class Signup(Handler):
    global newuser
    def get(self):
        self.render("signup.html", username= "", password= "", verify= "", email= "", failusername= "", failpassword= "", failverify= "", failemail= "")
    def post(self):
        UsersDB_list = []
        UsersDB_db = db.GqlQuery("select * from UsersDB")
        for e in UsersDB_db:
            UsersDB_list.append(str(e.username))
        v_username = valid_username(self.request.get("username"))
        v_password = valid_password(self.request.get("pasword"))
        v_verify = (self.request.get("verify") == self.request.get("password"))
        v_email = valid_email(self.request.get("email"))
        if self.request.get("username") not in UsersDB_list:
            if not v_username or not self.request.get("username"):
                self.render("signup.html", username = "", password = "", verify= "", email="", failusername="Ponlo bien o dejemo eto'",failpassword= "", failverify= "", failemail= "")
            else:
                if not self.request.get("password") or len(self.request.get("password")) < 3:
                    self.render("signup.html", username= self.request.get("username"), verify= "", email= "", failusername= "",failpassword= "Deja el relajo ya manin, ponla bien", failverify= "", failemail= "")
                else:
                    if not v_verify:
                        self.render("signup.html", username= self.request.get("username"), password= self.request.get("password"), verify= "", email= "", failusername= "",failpassword= "", failverify= "Revisala que ta' mala", failemail= "")
                    else:
                        if v_email == False:
                            self.render("signup.html", failemail= "Si lo va a poner mal mejor no ponga' na'", username= self.request.get("username"), password= self.request.get("password"), verify= "", email= "",failusername= "", failpassword= "", failverify= "")
                        else:
                            new_user = UsersDB(username = self.request.get("username"), password = hashlib.sha256(str(self.request.get("password"))).hexdigest())
                            new_user.put()
                            self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (str(new_user.key().id()),hashlib.sha256(str(new_user.key().id())).hexdigest()))
                            self.redirect("/welcome")
        else:
            self.render("signup.html", username = "", password = "", verify= "", email="", failusername="Este usuario ya existe",failpassword= "", failverify= "", failemail= "")
class Login(Handler):
    def get(self):
        if self.request.cookies.get("user_id") == "" or not self.request.cookies.get("user_id"):
            self.render("login.html")
        else:
            self.redirect("/welcome")
    def post(self):
        UsersDB_db = db.GqlQuery("select * from UsersDB")
        UsersDB_list = {}
        for e in UsersDB_db:
            UsersDB_list[e.username] = [e.username, e.password, e.key().id()]
        if self.request.get("username") in UsersDB_list:
            password = UsersDB_list[self.request.get("username")][1]
            key = UsersDB_list[self.request.get("username")][2]
            if hashlib.sha256(self.request.get("password")).hexdigest() == password:        
                self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (str(key),hashlib.sha256(str(key)).hexdigest()))
                self.redirect("/welcome")
            else:
                self.render("login.html", username = self.request.get("username"), failpassword = "Ta' mala")
        else:
            self.render("login.html", failusername = "Usuario no existente")

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/signup")

class NewPost(Handler):
    def get(self):
        if self.request.cookies.get("user_id") == "" or not self.request.cookies.get("user_id"):
            self.redirect("/signup")
        self.render("blog.html")
    def post(self):
        content = self.request.get("content")
        subject = self.request.get("subject")
        autor = db.get(db.Key.from_path("UsersDB", int(self.request.cookies.get("user_id").split("|")[0]))).username
        if content and subject:
            b = PostsDB(subject=subject,content=filter(content), autor=autor)
            b.put()
            self.redirect('/%s' % b.key().id())
        else:
            error = "Asunto y mensaje requeridos."
            self.render("blog.html", error=error, cont=content)

class Post(Handler):
    def get(self, post_id):
        key = db.Key.from_path('PostsDB', int(post_id))
        post = db.get(key)
        if not post:
            self.error(404)
            return
        
        self.render("showone.html", post=post)
        

class MainPage(Handler):
    def render_front(self, subject="", content="", autor= ""):
        blogs = db.GqlQuery("select * from PostsDB order by last_modified desc limit 8")
        if self.request.cookies.get("user_id") == "" or not self.request.cookies.get("user_id"):
            self.render("showblogs.html", blogs= blogs, userinfo = '<a href="/login">Iniciar sesion</a>')
        else:
            self.render("showblogs.html", blogs=blogs, userinfo = db.get(db.Key.from_path("UsersDB", int(self.request.cookies.get("user_id").split("|")[0]))).username + ' <a href="/logout">(salir)</a>')
        
    def get(self):
        self.render_front()

class PostsDB(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    autor = db.StringProperty(required = False)
    created = db.DateProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class Welcome(webapp2.RequestHandler):
    def get(self):
        if not self.request.cookies.get("user_id") or self.request.cookies.get("user_id") == "":
            self.error(404)
        else:
            user_id = str(self.request.cookies.get("user_id")).split("|")[0]
            key = db.Key.from_path('UsersDB', int(user_id))
            name = db.get(key).username
            if hashlib.sha256(user_id).hexdigest() == str(self.request.cookies.get("user_id")).split("|")[1]:
                self.response.write("<h2>Bienvenido, " + name + "!, ya puedes volver a <a href='/'>la pagina principal</a>") 

            else:
                self.redirect('/signup')
    
        

app = webapp2.WSGIApplication([
    ('/', MainPage), ('/newpost', NewPost), ('/([0-9]+)', Post), ('/logout', Logout), ('/signup', Signup), ('/login', Login), ('/welcome', Welcome)
], debug=True)
