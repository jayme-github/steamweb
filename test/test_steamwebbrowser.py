import os
import shutil
import unittest
import tempfile
import httpretty
import json
import datetime
import random
import string
import mock
from sys import version_info
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64decode
from png import Writer
from io import BytesIO

from steamweb.steamwebbrowser import SteamWebBrowser, SteamWebError, IncorrectLoginError

def random_ascii_string(lengh):
    ''' Return a random string
    May contain ASCII upper and lowercase as well as digits
    '''
    return ''.join(random.choice(
        string.ascii_letters + string.digits
        ) for i in range(lengh))

def random_number(lengh):
    ''' Return a random numbe rwith fixed length of lengh '''
    range_start = 10**(lengh-1)
    range_end = (10**lengh)-1
    return random.randint(range_start, range_end)

class SteamWebBrowserMocked(SteamWebBrowser):
    ''' Mocked SteamWebBrowser
    '''
    def __init__(self, user, password):
        # Generate an RSA key
        self.rsa_full = RSA.generate(2048)
        self.cipher_full = PKCS1_v1_5.new(self.rsa_full)
        self._content_type_json = 'application/json; charset=utf-8'
        self._login_stage = ['email', 'twocfactor', 'captcha']
        self._steamid = str(random_number(17))

        # Register URIs
        httpretty.register_uri(httpretty.POST, 'https://steamcommunity.com/mobilelogin/getrsakey/',
                                body=json.dumps({
                                        'success': True,
                                        'publickey_mod': format(self.rsa_full.n, 'x').upper(),
                                        'publickey_exp': format(self.rsa_full.e, 'x').upper(),
                                        'timestamp': '64861350000', # TODO don't know how this is constructed
                                }),
                                content_type=self._content_type_json)

        httpretty.register_uri(httpretty.POST, 'https://steamcommunity.com/mobilelogin/dologin/',
                                body=self.generate_dologin_response)

        httpretty.register_uri(httpretty.GET, 'https://steamcommunity.com/public/captcha.php',
                                body=self.generate_captcha_response,
                                adding_headers={
                                    'Set-Cookie': 'sessionid=%s; path=/' % (
                                        random_ascii_string(24),
                                    ),
                                })

        httpretty.register_uri(httpretty.POST, 'https://steamcommunity.com/login/transfer',
                                body='Success',
                                status=200)

        super(SteamWebBrowserMocked, self).__init__(user, password)

    def __enter__(self):
        httpretty.enable()
        return self

    def __exit(self, exc_type, exc_val, exc_tb):
        httpretty.disable()

    def generate_dologin_response(self, request, uri, headers):
        ''' Generate dologin responses
        '''
        if self._login_stage:
            stage = self._login_stage.pop(0)
            if stage == 'email':
                data = {
                    'success': False,
                    'requires_twofactor': False,
                    'message': '',
                    'emailauth_needed': True,
                    'emaildomain': 'whoooohooo.com',
                    'emailsteamid': self._steamid,
                }
            elif stage == 'twocfactor':
                # FIXME: Don't know what is actually returned if twofactor is required
                data = {
                    'success': False,
                    'requires_twofactor': True,
                    'message': '',
                    'emailauth_needed': False,
                }
            elif stage == 'captcha':
                # FIXME: Don't know what is actually returned if captcha is required
                data = {
                    'success': False,
                    'requires_twofactor': False,
                    'message': '',
                    'emailauth_needed': False,
                    'captcha_needed': True,
                    'captcha_gid': str(random_number(18)),
                }
        else:
            # Processed all stages, login completed now
            data = {
                'success': True,
                'requires_twofactor': False,
                'login_complete': True,
                'redirect_uri': 'steammobile://mobileloginsucceeded',
                'oauth': json.dumps({
                    'steamid': self._steamid,
                    'oauth_token': random_ascii_string(32).lower(),
                    'wgtoken': random_ascii_string(40).upper(),
                    'wgtoken_secure': random_ascii_string(40).upper(),
                }),
            }

        next_year = (datetime.datetime.now() + datetime.timedelta(days=365))
        headers['Content-Type'] = self._content_type_json
        headers['Set-Cookie'] = 'browserid=%d; expires=%s; path=/' % (random_number(18), next_year.strftime('%a, %d-%b-%Y %H:%M:%S GMT'))
        return (200, headers, json.dumps(data))

    def generate_captcha_response(self, request, uri, headers):
        ''' Generate a PNG image and return it as captcha mock
        '''
        f = BytesIO()
        w = Writer(206, 40)
        pngdata = [[random.randint(0,255) for i in range(206*w.planes)] for i in range(40)]
        w.write(f, pngdata)
        headers['Content-Type'] = 'image/png'
        return (200, headers, f.getvalue())


class TestSteamWebBrowser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.environ['STEAMWEBROWSER_HOME'] = self.temp_dir

    def tearDown(self):
        if os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_appdata_path(self):
        ''' Test if appdata path is created '''
        appdata_paths = ('STEAMWEBROWSER_HOME', 'APPDATA', 'XDG_CONFIG_HOME', 'HOME')
        for key in appdata_paths:
                temp_dir = tempfile.mkdtemp()
                with mock.patch.dict('os.environ', {key: temp_dir}):
                    # Remove all other keys from environ
                    for a in appdata_paths:
                        if a != key and a in os.environ:
                            del os.environ[a]

                    swb = SteamWebBrowser('user', 'password')
                    self.assertTrue(os.path.isdir(swb.appdata_path))
                    self.assertTrue(os.access(swb.appdata_path, os.W_OK))

    @httpretty.activate
    def test_not_logged_in(self):
        httpretty.register_uri(httpretty.HEAD, 'https://store.steampowered.com/login/',
                                status=200)
        swb = SteamWebBrowser('user', 'password')
        self.assertFalse(swb.logged_in())

    @httpretty.activate
    def test_rsa_fail(self):
        httpretty.register_uri(httpretty.POST, 'https://steamcommunity.com/mobilelogin/getrsakey/',
                                body='{"success": false}',
                                content_type='application/json; charset=utf-8')
        swb = SteamWebBrowser('user', 'password')
        with self.assertRaises(SteamWebError):
            swb._get_rsa_key()

    @httpretty.activate
    def test_login(self):
        swb = SteamWebBrowserMocked('user', 'password')

        # Text if encryption works
        ciphertext = b64decode(swb._get_encrypted_password())
        self.assertEqual(swb.cipher_full.decrypt(ciphertext, None), swb._password)

        class StringStartingWith(str):
            def __eq__(self, other):
                return other.startswith(self)

        if version_info.major >= 3:
            input_func = 'builtins.input'
        else:
            input_func = 'steamweb.steamwebbrowser.input'
        with mock.patch(input_func, return_value='s3cretCode') as mock_input:
            # Test login
            swb.login()

            mock_input.assert_has_calls([
                mock.call(StringStartingWith('Please enter the code sent to your mail address at ')),
                mock.call('Please enter the code sent to your phone: '),
                mock.call(StringStartingWith('Please take a look at the captcha image "')),
            ])

            # Test if cookies where stored
            self.assertTrue(swb._has_cookie('browserid'))
    
    @httpretty.activate
    def test_login_failed(self):
        swb = SteamWebBrowserMocked('user', 'password')
        httpretty.register_uri(httpretty.POST, 'https://steamcommunity.com/mobilelogin/dologin/',
                                body='{"success": false,"message":"Incorrect login."}')
        with self.assertRaises(IncorrectLoginError):
            swb.login()
