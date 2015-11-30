from __future__ import print_function
import time
import re
import os
import stat
import logging
from requests import Session
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64encode
from sys import version_info
import json
if version_info.major >= 3: # Python 3
    from http.cookiejar import LWPCookieJar, Cookie
    import configparser
    from weakref import finalize
else: # Python 2
    from cookielib import LWPCookieJar, Cookie
    import ConfigParser as configparser
    from builtins import input, int # pylint:disable=redefined-builtin
    def finalize(obj, func, *args, **kwargs): # pylint:disable=unused-argument
        ''' Stub method as there is no weakref.finalize in Python 2 '''
        pass

DEFAULT_USERAGENT = 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'

class SteamWebError(Exception):
    ''' Base class for exceptions in this module. '''
    pass

class LoginFailedError(SteamWebError):
    ''' Raised when the login failed (for whatever reason) '''
    pass

class IncorrectLoginError(LoginFailedError):
    ''' Raised when credentials are wrong '''
    pass

class InputError(SteamWebError):
    ''' Base class for input errors '''
    pass

class NoCaptchaCodeError(InputError):
    ''' Raised when no captcha code was given '''
    pass

class NoEmailCodeError(InputError):
    ''' Raised when no email code was given '''
    pass

class NoTwoFactorCodeError(InputError):
    ''' Raised then no two factor code was given '''
    pass

class SteamWebBrowser(object):
    name = 'SteamWebBrowser'
    browser = None
    rsa_cipher = None
    rsa_timestamp = None
    re_nonascii = re.compile(r'[^\x00-\x7F]')
    re_fs_safe = re.compile(r'[^\w-]')
    mobile_cookies = (
        Cookie(version=0, name='forceMobile', value='1',
            port=None, port_specified=False,
            domain='steamcommunity.com', domain_specified=True, domain_initial_dot=False,
            path='/mobilelogin', path_specified=True,
            secure=False, expires=None, discard=False, comment=None, comment_url=None, rest={},
        ),
        Cookie(version=0, name='mobileClient', value='Android',
            port=None, port_specified=False,
            domain='steamcommunity.com', domain_specified=True, domain_initial_dot=False,
            path='/mobilelogin', path_specified=True,
            secure=False, expires=None, discard=False, comment=None, comment_url=None, rest={},
        ),
    )

    def __init__(self, username=None, password=None):
        self._username = self._remove_nonascii(username)
        self._password = self._remove_nonascii(password)
        self.logger.info('Initialized with user: %s', self._username)

        self.session = Session()
        # urllib3 will sleep for {backoff factor} * (2 ^ ({number of total retries} - 1)) seconds between attempts.
        self.session.mount('http://', HTTPAdapter(
            max_retries=Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        ))
        self.session.mount('https://', HTTPAdapter(
            max_retries=Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        ))
        self.set_useragent()
        # Avoid ResourceWarning: unclosed <ssl.SSLSocket ...> with python 3
        finalize(self, self.session.close)

        cookie_file = os.path.join(self.appdata_path, self._make_fs_safe(username)+'.lwp')
        self.session.cookies = LWPCookieJar(cookie_file)
        if not os.path.exists(cookie_file):
            # initialize new cookie file
            self.logger.info('Creating new cookie file: "%s"', cookie_file)
            self.set_mobile_cookies()
            self._save_cookies()
            os.chmod(cookie_file,  stat.S_IRUSR | stat.S_IWUSR)
        else:
            # load cookies
            self.logger.info('Loading cookies from file: "%s"', cookie_file)
            self.session.cookies.load(ignore_discard=True)
            if not self._has_cookie('forceMobile') or not self._has_cookie('mobileClient'):
                self.clear_mobile_cookies()
                self.set_mobile_cookies()
                self._save_cookies()

    @property
    def oauth_access_token(self):
        c = self._get_cookie('oauth_access_token', 'steamwebbrowser.tld')
        if c:
            return c.value
        raise AttributeError('oauth_access_token is not set')

    @property
    def steamid(self):
        c = self._get_cookie('steamid', 'steamwebbrowser.tld')
        if c:
            return c.value
        raise AttributeError('steamid is not set')

    @property
    def logger(self):
        if not getattr(self, '_logger', False):
            name = '.'.join((__name__, self.__class__.__name__))
            self._logger = logging.getLogger(name)
        return self._logger

    def _save_cookies(self):
        self.logger.debug('Saving cookies to disk')
        return self.session.cookies.save(ignore_discard=True)

    @property
    def appdata_path(self):
        if not getattr(self, '_appdata_path', False):
            # Determine and create path if not exist
            if 'STEAMWEBROWSER_HOME' in os.environ:
                confighome = os.environ['STEAMWEBROWSER_HOME']
            elif 'APPDATA' in os.environ:
                confighome = os.environ['APPDATA']
            elif 'XDG_CONFIG_HOME' in os.environ:
                confighome = os.environ['XDG_CONFIG_HOME']
            else:
                confighome = os.path.join(os.environ['HOME'], '.config')
            # Store it for later reference and create it if it does not exist
            self._appdata_path = os.path.join(confighome, self.name)
            for p in [p for p in (confighome, self._appdata_path) if not os.path.isdir(p)]:
                os.mkdir(p, stat.S_IRWXU)
        self.logger.info('Appdata path: "%s"', self._appdata_path)
        return self._appdata_path

    def set_useragent(self, useragent=DEFAULT_USERAGENT):
        self.session.headers.update({'User-Agent': useragent})
        self.logger.debug('User-Agent set to: "%s"', useragent)

    def clear_mobile_cookies(self):
        for mc in self.mobile_cookies:
            for c in self.session.cookies:
                if c.name == mc.name and \
                        c.domain == mc.domain:
                    # Remove cookie
                    self.session.cookies.clear(c.domain, c.path, c.name)

    def set_mobile_cookies(self):
        for mc in self.mobile_cookies:
            self.session.cookies.set_cookie(mc)

    def post(self, url, data=None, **kwargs):
        self.logger.debug('POST "%s", data: "%s", kwargs: "%s"', url, data, kwargs)
        h = self._hash_cookies()
        r = self.session.post(url, data, **kwargs)
        # Will raise HTTPError on 4XX client error or 5XX server error response
        r.raise_for_status()
        if h != self._hash_cookies():
            # Cookies have changed
            self._save_cookies()
        if r.history and 'login/home/?goto=' in r.url:
            # Session expired, login again
            self.logger.warning('Session expired while POST, trying to login again')
            if self.login():
                return self.post(url, data, **kwargs)
            else:
                self.logger.error('Login failed during POST')
        else:
            return r

    def get(self, url, **kwargs):
        self.logger.debug('GET "%s", kwargs: "%s"', url, kwargs)
        h = self._hash_cookies()
        r = self.session.get(url, **kwargs)
        # Will raise HTTPError on 4XX client error or 5XX server error response
        r.raise_for_status()
        if h != self._hash_cookies():
            # Cookies have changed
            self._save_cookies()
        if r.history and 'login/home/?goto=' in r.url:
            # Session expired, login again
            self.logger.warning('Session expired while GET, trying to login again')
            if self.login():
                return self.get(url, **kwargs)
            else:
                self.logger.error('Login failed during GET')
        else:
            return r

    def get_account_page(self):
        return self.get('https://store.steampowered.com/account/')

    def get_profile_page(self):
        return self.get('https://steamcommunity.com/my/')

    def _remove_nonascii(self, instr):
        ''' Steam strips non-ascii characters before sending across the web.
        '''
        return self.re_nonascii.sub('', instr).encode('ascii')
    
    def _make_fs_safe(self, instr):
        ''' Returns a very conservative filesystem-safe name for instr.
        It avoids most non-word or digit values as is max. 27 characters long
        '''
        instr = self.re_fs_safe.sub('', instr)
        return instr[:27] # 27 + '.lwp' = 31, considered maximum
    
    @staticmethod
    def _get_donotcachetime():
        return int(round(time.time() * 1000))

    def _log_cookies(self, prefix=''):
        for c in self.session.cookies:
            self.logger.debug('%s: %s', prefix, repr(c))

    def _get_cookie(self, name, domain):
        ''' Return the cookie "name" for "domain" if found
            If there are mote than one, only the first is returned
        '''
        for c in self.session.cookies:
            if c.name==name and c.domain==domain:
                return c
        return None

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
        url = 'https://steamcommunity.com/mobilelogin/getrsakey/'
        values = {
                'username': self._username,
                'donotcache' : self._get_donotcachetime(),
        }
        req = self.post(url, data=values)
        data = req.json()
        if not data['success']:
            raise SteamWebError('Failed to get RSA key', data)
        # Construct RSA and cipher
        mod = int(str(data['publickey_mod']), 16)
        exp = int(str(data['publickey_exp']), 16)
        rsa = RSA.construct((mod, exp))
        self.rsa_cipher = PKCS1_v1_5.new(rsa)
        self.rsa_timestamp = data['timestamp']

    def _get_encrypted_password(self):
        if not self.rsa_cipher:
            self._get_rsa_key()
        # str.encode('base64') returns a formatted string (including newlines) so use b64encode instead
        return b64encode(self.rsa_cipher.encrypt(self._password))

    def logged_in(self):
        try:
            getattr(self, 'oauth_access_token')
        except AttributeError:
            self.logger.debug('No access token stored')
            return False
        # Use session directly as self.get() will trigger login if not logged in
        r = self.session.get('https://steamcommunity.com/my/')
        self.logger.debug('Request headers: %s', r.headers)
        if '<a class="global_action_link"' not in r.text:
            return True
        return False

    @staticmethod
    def _handle_captcha(captcha_data, message=''): # pylint:disable=unused-argument
        ''' Called when a captcha must be solved
        Writes the image to a temporary file and asks the user to enter the code.

        Args:
            captcha_data: Bytestring of the PNG captcha image.
            message: Optional. A message from Steam service.

        Returns:
            A string containing the solved captcha code.
        '''
        from tempfile import NamedTemporaryFile
        tmpf = NamedTemporaryFile(suffix='.png')
        tmpf.write(captcha_data)
        tmpf.flush()
        captcha_text = input('Please take a look at the captcha image "%s" and provide the code:' % tmpf.name)
        tmpf.close()
        return captcha_text

    @staticmethod
    def _handle_emailauth(maildomain='', message=''): # pylint:disable=unused-argument
        ''' Called when SteamGuard requires authentication via e-mail.
        Asks the user to enter the code.

        Args:
            maildomain: Optional. The mail domain of the e-mail address the SteamGuard
                code is send to.
            message: Optional. A message from Steam service.

        Returns:
            A string containing the code.
        '''
        print('SteamGuard requires email authentication...')
        emailauth = input('Please enter the code sent to your mail address at "%s": ' % maildomain)
        emailauth.upper()
        return emailauth

    @staticmethod
    def _handle_twofactor(message=''): # pylint:disable=unused-argument
        ''' Called when SteamGuard requires two-factor authentication..
        Asks the user to enter the code.

        Args:
            message: Optional. A message from Steam service.

        Returns:
            A string containing the code.
        '''
        print('SteamGuard requires mobile authentication...')
        twofactorcode = input('Please enter the code sent to your phone: ')
        twofactorcode.upper()
        return twofactorcode

    def _store_oauth_access_token(self, oauth_access_token):
        ''' Called when login is complete to store the oauth access token
            This implementation stores the oauth_access_token in a seperate cookie for domain steamwebbrowser.tld
        '''
        c = Cookie(version=0, name='oauth_access_token', value=oauth_access_token,
            port=None, port_specified=False,
            domain='steamwebbrowser.tld', domain_specified=True, domain_initial_dot=False,
            path='/', path_specified=True,
            secure=False, expires=None, discard=False, comment=None, comment_url=None, rest={},
        )
        self.session.cookies.set_cookie(c)
        self._save_cookies()

    def _store_steamid(self, steamid):
        ''' Called when login is complete to store the steam id
            This implementation stores the steamid in a seperate cookie for domain steamwebbrowser.tld
        '''
        c = Cookie(version=0, name='steamid', value=steamid,
            port=None, port_specified=False,
            domain='steamwebbrowser.tld', domain_specified=True, domain_initial_dot=False,
            path='/', path_specified=True,
            secure=False, expires=None, discard=False, comment=None, comment_url=None, rest={},
        )
        self.session.cookies.set_cookie(c)
        self._save_cookies()

    def login(self, captchagid='-1', captcha_text='', emailauth='', emailsteamid='', 
                loginfriendlyname='', twofactorcode=''): # pylint:disable=too-many-arguments
        self.logger.info('login calles with: captchagid="%s", captcha_text="%s", emailauth="%s",'
                        ' emailsteamid="%s", loginfriendlyname="%s", twofactorcode="%s"',
                        captchagid, captcha_text, emailauth, emailsteamid, loginfriendlyname,
                        twofactorcode,
        )
        # Force a new RSA key request for every call
        self._get_rsa_key()

        # Login
        url = 'https://steamcommunity.com/mobilelogin/dologin/'
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
                'oauth_client_id': 'DE45CD61',
        }

        req = self.post(url, data=values)
        self.logger.debug('login response: "%s"', req.text)
        data = req.json()
        self.logger.debug('JSON login response: "%s"', data)
        if data.get('message'):
            self.logger.warning(data.get('message'))
            if data.get('message') == 'Incorrect login.':
                raise IncorrectLoginError(data.get('message'))

        if data['success'] == True and data['oauth']:
            '''
            Save OAuth data which is a string containing json:

            steamid:         [STR] The user's SteamID
            oauth_token:     [STR] The OAuth token used for repeat authentication, and all secure requests.
            wgtoken_secure:  [STR] Cookie used to maintain secure access to steam's normal services (store, profile, settings, etc).
                                   This is to be set whenever a steam page is loaded (stored as cookie:steamLoginSecure="<SteamID>||<wgtoken_secure>").
            wgtoken:         [STR] Cookie used to maintain access to steam's public services.
                                   This is to be set whenever a steam page is loaded (steamLogin="<SteamID>||<wgtoken_secure>").
            '''
            oauth_json = json.loads(data['oauth'])
            self.logger.debug('JSON Oauth: "%s"', oauth_json)
            self._store_oauth_access_token(oauth_json['oauth_token'])
            self._store_steamid(oauth_json['steamid'])
            self.logger.info('Login completed, steamid: "%s"', self.steamid)
            # Logged in
            return self.steamid

        elif data.get('captcha_needed') == True and data.get('captcha_gid', '-1') != '-1':
            imgdata = self.get('https://steamcommunity.com/public/captcha.php',
                                        params={'gid': data['captcha_gid']})
            captcha_text = self._handle_captcha(captcha_data=imgdata.content, message=data.get('message', ''))
            self.logger.info('Got captcha text "%s"', captcha_text)
            if not captcha_text:
                raise NoCaptchaCodeError('Captcha code not provided.')
            return self.login(captchagid=data['captcha_gid'], captcha_text=captcha_text)

        elif data.get('emailauth_needed') == True:
            emailauth = self._handle_emailauth(maildomain=data['emaildomain'], message=data.get('message', ''))
            self.logger.info('Got e-mail code: "%s"', emailauth)
            if not emailauth:
                raise NoEmailCodeError('E-mail code not provided.')
            return self.login(emailauth=emailauth, emailsteamid=data['emailsteamid'])

        elif data.get('requires_twofactor') == True:
            twofactorcode = self._handle_twofactor(message=data.get('message', ''))
            self.logger.info('Got twofactor code: "%s"', twofactorcode)
            if not twofactorcode:
                raise NoTwoFactorCodeError('Two factor code not provided.')
            return self.login(twofactorcode=twofactorcode)

        else:
            raise LoginFailedError('Unable to login', data)

class SteamWebBrowserCfg(SteamWebBrowser):
    ''' SteamWebBrowser with built-in config file support
    '''
    def __init__(self):
        self.cfg = configparser.ConfigParser()
        self.cfg_path = os.path.join(self.appdata_path, 'config.cfg')
        if os.path.isfile(self.cfg_path):
            self.cfg.read(self.cfg_path)
        self._init_config()

        # Init superclass with username and password from config
        super(SteamWebBrowserCfg, self).__init__(
                self.cfg.get('steamweb', 'username').strip(),
                self.cfg.get('steamweb', 'password').strip()
        )
        # Overwrite User-Agent with the one in config
        self.set_useragent(self.cfg.get('steamweb', 'useragent'))

    def _init_config(self):
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
            self._write_config()
        os.chmod(self.cfg_path, stat.S_IRUSR | stat.S_IWUSR)

    def _write_config(self):
        with open(self.cfg_path, 'w') as cfg_fd:
            self.cfg.write(cfg_fd)

    def _store_oauth_access_token(self, oauth_access_token):
        self.cfg.set('steamweb', 'oauth_access_token', oauth_access_token)
        self._write_config()

    def _store_steamid(self, steamid):
        self.cfg.set('steamweb', 'steamid', steamid)
        self._write_config()

    @property
    def oauth_access_token(self):
        if self.cfg.has_option('steamweb', 'oauth_access_token'):
            return self.cfg.get('steamweb', 'oauth_access_token')
        raise AttributeError('oauth_access_token is not set')

    @property
    def steamid(self):
        if self.cfg.has_option('steamweb', 'steamid'):
            return self.cfg.get('steamweb', 'steamid')
        raise AttributeError('steamid is not set')

