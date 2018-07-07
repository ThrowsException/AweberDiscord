import bcrypt
import concurrent.futures
import json
import os
import urllib

import arrow
import psycopg2
import psycopg2.extras
from tornado import gen
import tornado.auth
import tornado.concurrent
import tornado.ioloop
import tornado.web
from tornado.httpclient import AsyncHTTPClient

conn = ''
DB_CONNECTION = os.environ.get('DB_CONNECTION',
                               'postgresql://postgres:example@localhost:5444')

executor = concurrent.futures.ThreadPoolExecutor(2)

try:
    conn = psycopg2.connect(DB_CONNECTION)
except:
    print("I am unable to connect to the database")


def get_token(aid):
    aid = str(aid)
    key = None
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as curs:
        curs.execute('''SELECT * FROM keys
                        WHERE aid = %s;''', (aid,))
        key = curs.fetchone()
    return key


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_id = self.get_secure_cookie("user")
        if user_id is None:
            return

        user_id = user_id.decode('utf8')
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as curs:
            curs.execute('''SELECT * FROM users
                            WHERE id = %s;''', (user_id,))
            return curs.fetchone()


class AWeberMixin(tornado.auth.OAuthMixin):

    _OAUTH_REQUEST_TOKEN_URL = 'https://auth.aweber.com/1.0/oauth/request_token'
    _OAUTH_AUTHORIZE_URL = 'https://auth.aweber.com/1.0/oauth/authorize'
    _OAUTH_ACCESS_TOKEN_URL = 'https://auth.aweber.com/1.0/oauth/access_token'
    _OAUTH_VERSION = '1.0a'

    def _oauth_consumer_token(self):
        return {
            'key': os.environ.get('CONSUMER_KEY', ''),
            'secret': os.environ.get('CONSUMER_SECRET', '')
        }

    @gen.coroutine
    def _oauth_get_user_future(self, access_token):
        r = yield self.aweber_request('https://api.aweber.com/1.0/accounts',
                                      access_token=access_token)

        r = tornado.escape.json_decode(r.body)
        aid = r['entries'][0]['id']

        with conn.cursor() as curs:
            curs.execute(f'''INSERT INTO keys(aid, key, secret, user_id)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT (aid)
                            DO UPDATE SET
                                (key, secret, user_id)
                                 = (EXCLUDED.key, EXCLUDED.secret, {self.current_user["id"]});''',
                            (aid, access_token['key'], access_token['secret'], self.current_user["id"]))
            conn.commit()
        return {'user': r}

    @gen.coroutine
    def aweber_request(self,
                       url, access_token=None, post_args=None, **args):
        if access_token:
            all_args = {}
            all_args.update(args)
            all_args.update(post_args or {})
            method = "POST" if post_args is not None else "GET"
            oauth = self._oauth_request_parameters(
                url, access_token, all_args, method=method)
            args.update(oauth)
        if args:
            url += "?" + urllib.parse.urlencode(args)

        client = self.get_auth_http_client()

        response = ''
        if method == 'POST':
            response = yield client.fetch(
                url, raise_error=False, method="POST",
                body=urllib.parse.urlencode(post_args))
        else:
            response = yield client.fetch(url, raise_error=False)

        return response

class Discord(object):
    API_ENDPOINT = 'https://discordapp.com/api/v6'

    @gen.coroutine
    def list_channels(self, guild_id):
        headers = {
            'Authorization': 'Bot {}'.format(os.environ.get('BOT_TOKEN', '')),
            'User-Agent': 'DiscordBot (https://www.github.com/throwsexception 6) Python'
        }
        http_client = AsyncHTTPClient()
        response = yield http_client.fetch(
            f'{self.API_ENDPOINT}/guilds/{guild_id}/channels',
            headers=headers)

        return tornado.escape.json_decode(response.body)


class BroadcastHandler(tornado.web.RequestHandler, AWeberMixin):
    @gen.coroutine
    def get(self, aid):
        access_token = get_token(aid)
        r = yield self.aweber_request(
            f'https://api.aweber.com/1.0/accounts/{aid}/lists/{access_token["list_id"]}/broadcasts',
            access_token, status='sent')

        self.set_header('Content-Type', 'application/json')
        self.write(r.body)

    @gen.coroutine
    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as curs:
            curs.execute('''
            SELECT *
            FROM users
            JOIN keys on user_id = id
            WHERE channel_id = %s
            ''', (data["channel"], ))
            account = curs.fetchone()
        access_token = get_token(account["aid"])
        if account:
            broadcast = {
                'body_html': '',
                'body_text': f'{data["message"]}',
                'subject': f'{data["subject"]}'
            }

            r = yield self.aweber_request(
                f'https://api.aweber.com/1.0/accounts/{account["aid"]}/lists/{account["list_id"]}/broadcasts',
                access_token, method='POST', post_args=broadcast)

            r = tornado.escape.json_decode(r.body)
            utc = arrow.utcnow()
            send = utc.shift(minutes=2)
            schedule = yield self.aweber_request(
                f'''https://api.aweber.com/1.0/accounts/{account["aid"]}/lists/{account["list_id"]}/broadcasts/{r["broadcast_id"]}/schedule''',
                access_token, method='POST', post_args={'scheduled_for': send})
            self.set_header('Content-Type', 'application/json')
            self.write(schedule.body)
        else:
            self.set_status(500, 'channel not found')


class AuthHandler(BaseHandler, AWeberMixin):
    @gen.coroutine
    @tornado.web.authenticated
    def get(self):
        if self.get_argument('oauth_token', None):
            r = yield self.get_authenticated_user()
            self._on_auth(r)
            return

        yield self.authorize_redirect(callback_uri='auth')

    def _on_auth(self, user):
        # self.set_secure_cookie("user", json.dumps(user))
        self.redirect("/")


class MainHandler(BaseHandler, AWeberMixin):
    @gen.coroutine
    @tornado.web.authenticated
    def get(self):
        guild_id = self.get_argument('guild_id', None)
        if guild_id is not None:
            with conn.cursor() as curs:
                curs.execute('''UPDATE keys set guild_id = %s WHERE user_id = %s''',
                             (guild_id, self.current_user['id'],))
                conn.commit()

        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as curs:
            curs.execute('''SELECT * FROM keys WHERE user_id = %s''',
                         (self.current_user['id'], ))
            account = curs.fetchone()
            channels = []

            if account and account['guild_id']:
                discord = Discord()
                channels = yield discord.list_channels(account['guild_id'])

            r = yield self.aweber_request(
                f'https://api.aweber.com/1.0/accounts/{account["aid"]}/lists',
                account)
            lists = tornado.escape.json_decode(r.body)

        self.render("home.html",
                    account=account,
                    channels=channels, lists=lists["entries"])

    @gen.coroutine
    @tornado.web.authenticated
    def post(self):
        channel = self.get_argument('channel', None)
        list_id = self.get_argument('list', None)
        if channel is not None:
            with conn.cursor() as curs:
                curs.execute('''UPDATE users set channel_id = %s WHERE id = %s''',
                             (channel, self.current_user['id'],))
                conn.commit()
            self.current_user['channel_id'] = channel
        if list_id is not None:
            with conn.cursor() as curs:
                curs.execute('''UPDATE users set list_id = %s WHERE id = %s''',
                             (list_id, self.current_user['id'],))
                conn.commit()
            self.current_user['list_id'] = list_id

        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as curs:
            curs.execute('''SELECT * FROM keys WHERE user_id = %s''',
                         (self.current_user['id'], ))
            account = curs.fetchone()
            channels = []

            if account and account['guild_id']:
                discord = Discord()
                channels = yield discord.list_channels(account['guild_id'])

            r = yield self.aweber_request(
                f'https://api.aweber.com/1.0/accounts/{account["aid"]}/lists',
                account)
            lists = tornado.escape.json_decode(r.body)

        self.render("home.html",
                    account=account,
                    channels=channels,
                    lists=lists["entries"])

class LoginHandler(BaseHandler):
    def get(self):
        self.render("login.html", error=None)

    @gen.coroutine
    def post(self):
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as curs:
            curs.execute('''SELECT * FROM users WHERE email = %s''',
                         (self.get_argument("email"), ))
            user = curs.fetchone()

        if user is None:
            self.render("login.html", error="email not found")
            return

        matches = yield executor.submit(
            bcrypt.checkpw, tornado.escape.utf8(self.get_argument("password")),
            tornado.escape.utf8(user['hashed_password']))
        if matches:
            self.set_secure_cookie("user", str(user['id']))
            self.redirect(self.get_argument("next", "/"))
        else:
            self.render("login.html", error="incorrect password")

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/login"))


class SignupHandler(BaseHandler):
    def get(self):
        self.render("signup.html")

    @gen.coroutine
    def post(self):
        hashed_password = yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            bcrypt.gensalt())

        with conn.cursor() as curs:
            curs.execute('''INSERT INTO users (email, name, hashed_password)
                            VALUES (%s, %s, %s)''',
                         (self.get_argument("email"), self.get_argument("name"),
                          tornado.escape.native_str(hashed_password)))
            conn.commit()
            user_id = curs.fetchone()[0]

        self.set_secure_cookie("user", str(user_id))
        self.redirect(self.get_argument("next", "/"))


settings = {
    "cookie_secret": os.environ.get('SECRET_COOKIE', ''),
    "login_url": "/login",
    "template_path": os.path.join(os.path.dirname(__file__), "templates"),
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
}


def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/auth", AuthHandler),
        (r"/broadcast", BroadcastHandler),
        (r"/login", LoginHandler),
        (r"/logout", LogoutHandler),
        (r"/signup", SignupHandler),
        (r"/discord", MainHandler),
    ], **settings)


if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
