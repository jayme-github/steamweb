from __future__ import print_function
import time
import re
import os
import sys
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64encode
if sys.version_info >= (3, 0): # Python 3
    from http.cookiejar import LWPCookieJar
    import configparser
else: # Python 2
    from cookielib import LWPCookieJar
    import ConfigParser as configparser
    from builtins import input, int

class SteamWebBrowser(object):
    cfg = None
    browser = None
    rsa_cipher = None
    rsa_timestamp = None
    re_nonascii = re.compile(r'[^\x00-\x7F]')

    def __init__(self):
        self.cfg_dir = self._build_config_path()
        self.cfg = configparser.ConfigParser()
        cfg_path = os.path.join(self.cfg_dir, 'config.cfg')
        cookie_file = os.path.join(self.cfg_dir, 'cookies.lwp')
        if os.path.isfile(cfg_path):
            self.cfg.read(cfg_path)
        self._init_config(cfg_path)

        self.session = requests.Session()
        self.session.mount("http://", requests.adapters.HTTPAdapter(max_retries=2))
        self.session.mount("https://", requests.adapters.HTTPAdapter(max_retries=2))

        self.session.headers.update({'User-Agent' : self.cfg.get('steamweb', 'useragent')})
        self.session.cookies = LWPCookieJar(cookie_file)
        if not os.path.exists(cookie_file):
            # initialize new (empty) cookie file
            self._save_cookies()
        else:
            # load cookies
            self.session.cookies.load(ignore_discard=True)

    def _save_cookies(self):
        return self.session.cookies.save(ignore_discard=True)

    def _build_config_path(self):
        if 'APPDATA' in os.environ:
            confighome = os.environ['APPDATA']
        elif 'XDG_CONFIG_HOME' in os.environ:
            confighome = os.environ['XDG_CONFIG_HOME']
        else:
            confighome = os.path.join(os.environ['HOME'], '.config')
        cfg_dir = os.path.join(confighome, self.__class__.__name__)
        for p in [p for p in (confighome, cfg_dir) if not os.path.isdir(p)]:
            os.mkdir(p, 0o700)
        return cfg_dir

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
        if not self.cfg.has_option('steamweb', 'tkinter'):
            tkinter = raw_input('Run Tkinter? ')
            if tkinter.lower() in ['yes', 'y', 'true', 't']:
               self.cfg.set('steamweb', 'tkinter', True)
            else:
               self.cfg.set('steamweb', 'tkinter', False)
            cfg_changed = True
        if not self.cfg.has_option('steamweb', 'useragent'):
            self.cfg.set(
                'steamweb',
                'useragent',
                'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'
            )
            cfg_changed = True

        if cfg_changed:
            with open(cfg_path, 'wb') as cfg_fd:
                self.cfg.write(cfg_fd)

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

    @property
    def _username(self):
        return self._remove_nonascii(self.cfg.get('steamweb', 'username').strip())

    @property
    def _password(self):
        return self._remove_nonascii(self.cfg.get('steamweb', 'password').strip())

    def _get_donotcachetime(self):
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
        #self._log_cookies('_get_rsa_key')
        if not req.ok:
            raise Exception('Failed to get RSA key: %d' % req.status_code)
        data = req.json()
        if not data['success']:
            raise Exception('Failed to get RSA key: %s' % data)
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
        r = self.get('https://store.steampowered.com/account/')
        # Will be redirected if not logged in
        return r.ok and r.url == 'https://store.steampowered.com/account/'

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
        if not req.ok:
            return
        #self._log_cookies('login')
        data = req.json()
        if 'message' in data:
            print('MSG:', data['message'])
            if data['message'] == 'Incorrect login.':
                return

        if data['success'] == True:
            # Transfer to get the cookies for the store page too
            data['transfer_parameters']['remember_login'] = True
            req = self.post(data['transfer_url'], data['transfer_parameters'])
            if not req.ok:
                print('WARNING: transfer failed: "%s"' % req.content)

            # Logged in (at least a bit). Save cookies to disk
            #self._save_cookies()
            return True

        elif data.get('captcha_needed') == True and data.get('captcha_gid') != '-1':
            imgdata = self.get('https://steamcommunity.com/public/captcha.php',
                                        params={'gid': data['captcha_gid']})
            if not imgdata.ok:
                print('Failed to get captcha')
                return False
            from tempfile import NamedTemporaryFile
            tmpf = NamedTemporaryFile(suffix='.png')
            tmpf.write(imgdata.content)
            tmpf.flush()

            if self.cfg.get('steamweb', 'tkinter') == 'False':
                print('Please take a look at the captcha image "%s" and provide the code:' % tmpf.name)
                captcha_text = input('Enter code: ')
                tmpf.close()
                if captcha_text:
                    return self.login(captchagid=data['captcha_gid'], captcha_text=captcha_text)
                else:
                    print('No captcha code given')
                    return False
            else: # if self.cfg.get('steamweb', 'tkinter') == 'True'
                if sys.version_info >= (3, 0): # Python 3
                    import tkinter as tk
                else: # Python 2
                    import Tkinter as tk
                # pip install pillow
                from PIL.ImageTk import PhotoImage
                from PIL.Image import open as openImage

                tk_root = tk.Tk()
                def close(captcha_text):
                    if captcha_text.get() != '':
                        tk_root.destroy() # Faster than .quit() and won't be re-used anyways
                tk_root.title('')
                tk_root.configure(bg='black')
                captcha = PhotoImage(openImage(tmpf))
                tk.Label(tk_root, text=data['message'], bg='black', fg='white').pack()
                tk.Label(tk_root, image=captcha, bg='black').pack()
                captcha_text = tk.StringVar()
                tk.Entry(tk_root, textvariable = captcha_text, bg='black', fg='white', insertbackground='white').pack()
                tk_root.bind('<Return>', lambda s: close(captcha_text))
                tk_root.mainloop()
                tmpf.close()
                return self.login(captchagid=data['captcha_gid'], captcha_text=captcha_text.get())

        elif data.get('emailauth_needed') == True:
            print('SteamGuard requires email authentication...')
            print('Please enter the code sent to your mail addres at "%s":' % data['emaildomain'])
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
