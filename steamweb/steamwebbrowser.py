from __future__ import print_function
import time
import re
import os
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64encode
try:
    # Python 3
    from http.cookiejar import LWPCookieJar
except ImportError:
    # Python 2
    from cookielib import LWPCookieJar
try:
    # Python 3
    import configparser
except ImportError:
    # Python 2
    import ConfigParser as configparser

# Only needed when running Python 2
from builtins import input, int

DEFAULT_USERAGENT = 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'

class SteamWebBrowser(object):
    name = 'SteamWebBrowser'
    browser = None
    rsa_cipher = None
    rsa_timestamp = None
    re_nonascii = re.compile(r'[^\x00-\x7F]')

    def __init__(self, username=None, password=None):
        self._username = self._remove_nonascii(username)
        self._password = self._remove_nonascii(password)

        cookie_file = os.path.join(self.appdata_path, 'cookies.lwp')

        self.session = requests.Session()
        self.session.mount("http://", requests.adapters.HTTPAdapter(max_retries=2))
        self.session.mount("https://", requests.adapters.HTTPAdapter(max_retries=2))
        self.set_useragent()

        self.session.cookies = LWPCookieJar(cookie_file)
        if not os.path.exists(cookie_file):
            # initialize new (empty) cookie file
            self._save_cookies()
        else:
            # load cookies
            self.session.cookies.load(ignore_discard=True)

    def _save_cookies(self):
        return self.session.cookies.save(ignore_discard=True)

    @property
    def appdata_path(self):
        if not getattr(self, '_appdata_path', False):
            # Determine and create path if not exist
            if 'APPDATA' in os.environ:
                confighome = os.environ['APPDATA']
            elif 'XDG_CONFIG_HOME' in os.environ:
                confighome = os.environ['XDG_CONFIG_HOME']
            else:
                confighome = os.path.join(os.environ['HOME'], '.config')
            # Store it for later reference and create it if it does not exist
            self._appdata_path = os.path.join(confighome, self.name)
            for p in [p for p in (confighome, self._appdata_path) if not os.path.isdir(p)]:
                os.mkdir(p, 0o700)
        return self._appdata_path

    def set_useragent(self, useragent=DEFAULT_USERAGENT):
        self.session.headers.update({'User-Agent': useragent})

    def post(self, url, data=None, **kwargs):
        h = self._hash_cookies()
        r = self.session.post(url, data, **kwargs)
        if h != self._hash_cookies():
            # Cookies have changed
            self._save_cookies()
        return r

    def get(self, url, **kwargs):
        h = self._hash_cookies()
        r = self.session.get(url, **kwargs)
        if h != self._hash_cookies():
            # Cookies have changed
            self._save_cookies()
        return r

    def _remove_nonascii(self, instr):
        return self.re_nonascii.sub('', instr).encode('ascii')

    @staticmethod
    def _get_donotcachetime():
        return int(round(time.time() * 1000))

    def _log_cookies(self, prefix=''):
        for c in self.session.cookies:
            print(prefix, repr(c))

    def _has_cookie(self, name, domain='steamcommunity.com'):
        if len([c for c in self.session.cookies if c.name==name and c.domain==domain]) > 0:
            return True
        return False

    def _hash_cookies(self):
        ''' Returns the hash of a list of hashes from sorted repr() of every cookie in jar as
            LWPCookieJar does not change it's hash when cookies change.
        '''
        return hash(frozenset([hash(c) for c in sorted([repr(c) for c in self.session.cookies])]))

    def _get_rsa_key(self):
        ''' get steam RSA key, build and return cipher '''
        url = 'https://steamcommunity.com/login/getrsakey/'
        values = {
                'username': self._username,
                'donotcache' : self._get_donotcachetime(),
        }
        req = self.post(url, data=values)
        if req.ok:
            data = req.json()
            if data['success'] == True:
                # Construct RSA and cipher
                mod = int(str(data['publickey_mod']), 16)
                exp = int(str(data['publickey_exp']), 16)
                rsa = RSA.construct((mod, exp))
                self.rsa_cipher = PKCS1_v1_5.new(rsa)
                self.rsa_timestamp = data['timestamp']
            else:
                raise Exception('Failed to get RSA key: %s' % data)
        else:
            raise Exception('Failed to get RSA key: %d' % req.status_code)

    def _get_encrypted_password(self):
        if not self.rsa_cipher:
            self._get_rsa_key()
        # str.encode('base64') returns a formatted string (including newlines) so use b64encode instead
        return b64encode(self.rsa_cipher.encrypt(self._password))

    def logged_in(self):
        r = self.get('https://store.steampowered.com/account/')
        if r.ok:
            if r.url != 'https://store.steampowered.com/account/':
                # Will be redirected if not logged in
                return False
            else:
                return True
        return False

    def login(self, captchagid='-1', captcha_text='', emailauth='', emailsteamid='', loginfriendlyname='', twofactorcode=''):
        # Force a new RSA key request for every call
        self._get_rsa_key()

        # Login
        url = 'https://steamcommunity.com/login/dologin/'
        values = {
                'username': self._username,
                'password': self._get_encrypted_password(),
                'emailauth': emailauth, # SteamGuard email code
                'loginfriendlyname': loginfriendlyname, # SteamGuard "friendly" browser name
                'captchagid': captchagid, # ID of the captcha
                'captcha_text': captcha_text, # Captha text
                'emailsteamid': emailsteamid, # SteamGuard emailid
                'rsatimestamp': self.rsa_timestamp, # returned by getrsa call
                'remember_login': True,
                'donotcache': self._get_donotcachetime(),
                'twofactorcode' : twofactorcode,
        }
        req = self.post(url, data=values)
        if req.ok:
            data = req.json()
            if data.get('message'):
                print('MSG:', data.get('message'))
                if data.get('message') == 'Incorrect login.':
                    return

            if data['success']:
                # Transfer to get the cookies for the store page too
                data['transfer_parameters']['remember_login'] = True
                req = self.post(data['transfer_url'], data['transfer_parameters'])
                if not req.ok:
                    print('WARNING: transfer failed: "%s"' % req.content)

                # Logged in (at least a bit)
                return True

            elif data.get('captcha_needed', False) and data.get('captcha_gid', '-1') != '-1':
                imgdata = self.get('https://steamcommunity.com/public/captcha.php',
                                            params={'gid': data['captcha_gid']})
                if imgdata.ok:
                    from tempfile import NamedTemporaryFile
                    tmpf = NamedTemporaryFile(suffix='.png')
                    tmpf.write(imgdata.content)
                    tmpf.flush()
                    print('Please take a look at the captcha image "%s" and provide the code:' % tmpf.name)
                    captcha_text = input('Enter code: ')
                    tmpf.close()
                    if captcha_text:
                        return self.login(captchagid=data['captcha_gid'], captcha_text=captcha_text)
                    else:
                        print('No captcha code given')
                        return False
                else:
                    print('Failed to get captcha')
                    return False

            elif data.get('emailauth_needed', False):
                print('SteamGuard requires email authentication...')
                print('Please enter the code send to your mail addres at "%s":' % data['emaildomain'])
                emailauth = input('Enter code: ')
                emailauth.upper()
                if emailauth:
                    return self.login(emailauth=emailauth, emailsteamid=data['emailsteamid'])
                else:
                    print('No email auth code given')
                    return False
            elif data.get('requires_twofactor', False):
                print('SteamGuard requires mobile authentication...')
                twofactorcode = input('Please enter the code sent to your phone:')
                twofactorcode.upper()
                if twofactorcode:
                    return self.login(twofactorcode=twofactorcode)
            else:
                print('Error, could not login:', data)
                return False


class SteamWebBrowserCfg(SteamWebBrowser):
    ''' SteamWebBrowser with build in config file support
    '''
    def __init__(self):
        self.cfg = configparser.ConfigParser()
        cfg_path = os.path.join(self.appdata_path, 'config.cfg')
        if os.path.isfile(cfg_path):
            self.cfg.read(cfg_path)
        self._init_config(self.appdata_path)

        # Init superclass with username and password from config
        super(SteamWebBrowserCfg, self).__init__(
                self.cfg.get('steamweb', 'username').strip(),
                self.cfg.get('steamweb', 'password').strip()
        )
        # Overwrite User-Agent with the one in config
        self.set_useragent(self.cfg.get('steamweb', 'useragent'))

    def _init_config(self, cfg_path):
        cfg_changed = False
        if not self.cfg.has_section('steamweb'):
            self.cfg.add_section('steamweb')
            cfg_changed = True
        if not self.cfg.has_option('steamweb', 'username'):
            self.cfg.set('steamweb', 'username', input('Your Steam username: '))
            cfg_changed = True
        if not self.cfg.has_option('steamweb', 'password'):
            from getpass import getpass
            self.cfg.set('steamweb', 'password', getpass('Password: '))
            cfg_changed = True
        if not self.cfg.has_option('steamweb', 'useragent'):
            self.cfg.set(
                'steamweb',
                'useragent',
                DEFAULT_USERAGENT
            )
            cfg_changed = True

        if cfg_changed:
            with open(cfg_path, 'wb') as cfg_fd:
                self.cfg.write(cfg_fd)
