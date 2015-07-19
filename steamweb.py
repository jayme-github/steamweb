import time
import re
import os
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from cookielib import LWPCookieJar
import ConfigParser
from base64 import b64encode

class SteamWebBrowser(object):
    cfg = None
    browser = None
    rsa_cipher = None
    rsa_timestamp = None
    re_nonascii = re.compile(ur'[^\x00-\x7F]')

    def __init__(self):
        self.cfg = ConfigParser.ConfigParser()
        script_dir = os.path.dirname(__file__)
        cfg_path = os.path.join(script_dir, 'config.cfg')
        if os.path.isfile(cfg_path):
            self.cfg.read(cfg_path)
        self._init_config(cfg_path)
        
        user_agent = 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'
        cookie_file = os.path.join(script_dir, 'cookies.lwp')

        self.session = requests.Session()
        self.session.mount("http://", requests.adapters.HTTPAdapter(max_retries=2))
        self.session.mount("https://", requests.adapters.HTTPAdapter(max_retries=2))
        
        self.session.headers.update({'User-Agent' : user_agent})
        self.session.cookies = LWPCookieJar(cookie_file)
        if not os.path.exists(cookie_file):
            # initialize new (empty) cookie file
            self._save_cookies()
        else:
            # load cookies
            self.session.cookies.load(ignore_discard=True, ignore_expires=True)

    def __del___(self):
        self._save_cookies()

    def _save_cookies(self):
        return self.session.cookies.save(ignore_discard=True, ignore_expires=False)

    def _init_config(self, cfg_path):
        cfg_changed = False
        if not self.cfg.has_section('steamweb'):
            self.cfg.add_section('steamweb')
            cfg_changed = True
        if not self.cfg.has_option('steamweb', 'username'):
            self.cfg.set('steamweb', 'username', raw_input('Your Steam username: '))
            cfg_changed = True
        if not self.cfg.has_option('steamweb', 'password'):
            from getpass import getpass
            self.cfg.set('steamweb', 'password', getpass('Password: '))
            cfg_changed = True
        if cfg_changed:
            with open(cfg_path, 'wb') as cfg_fd:
                self.cfg.write(cfg_fd)

    def post(self, url, data=None, **kwargs):
        return self.session.post(url, data, **kwargs)

    def get(self, url, **kwargs):
        return self.session.get(url, **kwargs)

    def _remove_nonascii(self, instr):
        return self.re_nonascii.sub('', instr)

    @property
    def _username(self):
        return self._remove_nonascii(self.cfg.get('steamweb', 'username').strip())

    @property
    def _password(self):
        return self._remove_nonascii(self.cfg.get('steamweb', 'password').strip())

    def _get_donotcachetime(self):
        return int(round(time.time() * 1000))

    def _log_cookies(self, prefix):
        for c in self.session.cookies:
            print prefix, repr(c)

    def _has_cookie(self, name, domain='steamcommunity.com'):
        if len(filter(lambda x: x.name==name and x.domain==domain, self.session.cookies)) > 0:
            return True
        return False

    def _get_rsa_key(self):
        ''' get steam RSA key, build and return cipher '''
        url = 'https://steamcommunity.com/login/getrsakey/'
        values = {
                'username': self._username,
                'donotcache' : self._get_donotcachetime(),
        }
        req = self.post(url, data=values)
        #self._log_cookies('_get_rsa_key')
        if req.ok:
            data = req.json()
            if data['success'] == True:
                # Construct RSA and cipher
                mod = long(str(data['publickey_mod']), 16)
                exp = long(str(data['publickey_exp']), 16)
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
            #self._log_cookies('login')
            data = req.json()
            if data.get('message'):
                print 'MSG:', data.get('message')
                if data.get('message') == 'Incorrect login.':
                    return

            if data['success']:
                # Transfer to get the cookies for the store page too
                data['transfer_parameters']['remember_login'] = True
                req = self.post(data['transfer_url'], data['transfer_parameters'])
                if not req.ok:
                    print 'WARNING: transfer failed: "%s"' % req.content

                # Logged in (at least a bit). Save cookies to disk
                self._save_cookies()
                return True

            elif data.get('captcha_needed', False) and data.get('captcha_gid', '-1') != '-1':
                imgdata = self.get('https://steamcommunity.com/public/captcha.php',
                                            params={'gid': data['captcha_gid']})
                if imgdata.ok:
                    from tempfile import NamedTemporaryFile
                    tmpf = NamedTemporaryFile(suffix='.png')
                    tmpf.write(imgdata.content)
                    tmpf.flush()
                    print 'Please take a look at the captcha image "%s" and provide the code:' % tmpf.name
                    captcha_text = raw_input('Enter code: ')
                    tmpf.close()
                    if captcha_text:
                        return self.login(captchagid=data['captcha_gid'], captcha_text=captcha_text)
                    else:
                        print 'No captcha code given'
                        return False
                else:
                    print 'Failed to get captcha'
                    return False

            elif data.get('emailauth_needed', False):
                print 'SteamGuard requires email authentication...'
                print 'Please enter the code send to your mail addres at "%s":' % data['emaildomain']
                emailauth = raw_input('Enter code: ')
                emailauth.upper()
                if emailauth:
                    return self.login(emailauth=emailauth, emailsteamid=data['emailsteamid'])
                else:
                    print 'No email auth code given'
                    return False
            else:
                print 'Error, could not login:', data
                return False

if __name__ == '__main__':
    from bs4 import BeautifulSoup
    swb = SteamWebBrowser()
    if not swb.logged_in():
        swb.login()
    r = swb.get('https://store.steampowered.com/account/')
    soup = BeautifulSoup(r.content)
    print 'Yout wallet balance:', soup.find('div', attrs={'class': 'accountData price'}).get_text()
