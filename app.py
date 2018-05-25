import json
import os
import urllib

import arrow
import psycopg2
import psycopg2.extras
import tornado.auth
import tornado.concurrent
import tornado.ioloop
import tornado.web

conn = ''
DB_CONNECTION = os.environ.get('DB_CONNECTION',
                                'postgresql://postgres:example@localhost:5444')

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

class AWeberMixin(tornado.auth.OAuthMixin):

    _OAUTH_REQUEST_TOKEN_URL = 'https://auth.aweber.com/1.0/oauth/request_token'
    _OAUTH_AUTHORIZE_URL = 'https://auth.aweber.com/1.0/oauth/authorize';
    _OAUTH_ACCESS_TOKEN_URL = 'https://auth.aweber.com/1.0/oauth/access_token'
    _OAUTH_VERSION = '1.0a'

    def _oauth_consumer_token(self):
        return {
            'key': os.environ.get('CONSUMER_KEY', ''),
            'secret': os.environ.get('CONSUMER_SECRET', '')
        }

    @tornado.gen.coroutine
    def _oauth_get_user_future(self, access_token):
        r = yield self.aweber_request('https://api.aweber.com/1.0/accounts',
                                      access_token=access_token)

        r = tornado.escape.json_decode(r.body)
        aid = r['entries'][0]['id']

        with conn.cursor() as curs:
            curs.execute('''INSERT INTO keys(aid, key, secret)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (aid)
                            DO UPDATE SET
                                (key, secret)
                                 = (EXCLUDED.key, EXCLUDED.secret);''',
                            (aid, access_token['key'], access_token['secret']))
            conn.commit()
        return {'user': r}

    @tornado.gen.coroutine
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
            response = yield httpc.fetch(
                url, raise_error=False, method="POST",
                body=urllib.parse.urlencode(post_args))
        else:
            response = yield client.fetch(url, raise_error=False)

        return response


class BroadcastHandler(tornado.web.RequestHandler, AWeberMixin):
    @tornado.gen.coroutine
    def get(self, aid):
        access_token = get_token(aid)
        r = yield self.aweber_request(
            f'https://api.aweber.com/1.0/accounts/{aid}/lists/{access_token["list_id"]}/broadcasts',
            access_token, status='sent')

        self.set_header('Content-Type', 'application/json')
        self.write(r.body)

    @tornado.gen.coroutine
    def post(self, aid):
        access_token = get_token(aid)
        data = tornado.escape.json_decode(self.request.body)
        broadcast = {
            'body_html': '',
            'body_text': f'{data["message"]}',
            'subject': f'{data["subject"]}'
        }

        r = yield self.aweber_request(
            f'https://api.aweber.com/1.0/accounts/{aid}/lists/{access_token["list_id"]}/broadcasts',
            access_token, method='POST', post_args=broadcast)

        r = tornado.escape.json_decode(r.body)

        utc = arrow.utcnow()
        send = utc.shift(minutes=2)
        schedule = yield self.aweber_request(
            f'https://api.aweber.com/1.0/accounts/{aid}/lists/{access_token["list_id"]}/broadcasts/{r["broadcast_id"]}/schedule',
            access_token, method='POST', post_args={'scheduled_for': send})

        self.set_header('Content-Type', 'application/json')
        self.write(schedule.body)


class AuthHandler(tornado.web.RequestHandler, AWeberMixin):
    @tornado.gen.coroutine
    def get(self):
        if self.get_argument('oauth_token', None):
            r = yield self.get_authenticated_user()
            self._on_auth(r)
            return

        yield self.authorize_redirect(callback_uri='auth')

    def _on_auth(self, user):
        self.set_secure_cookie("u", json.dumps(user))
        self.set_secure_cookie("user", json.dumps(user))
        self.redirect("/")


settings = {
    "cookie_secret": os.environ.get('SECRET_COOKIE', ''),
    "login_url": "/auth",
}


def make_app():
    return tornado.web.Application([
        (r"/auth", AuthHandler),
        (r"/broadcast/(?P<aid>\d+)", BroadcastHandler),
    ], **settings)


if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
