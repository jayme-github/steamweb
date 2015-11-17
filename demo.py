#!/usr/bin/env python
from __future__ import print_function
import re
import sys
import logging

LOGFMT = '%(asctime)s (%(name)s.%(funcName)s) [%(levelname)s] %(message)s'
logging.basicConfig(format=LOGFMT, level=logging.DEBUG)
logging.getLogger('requests').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

from steamweb.steamwebbrowser import SteamWebBrowserCfg

if sys.version_info.major >= 3:
    from html.parser import HTMLParser
else:
    from HTMLParser import HTMLParser

swb = SteamWebBrowserCfg()
if not swb.logged_in():
    swb.login()
r = swb.get_account_page()
m = re.search(r'<a href="http://store\.steampowered\.com/account/history/">(\S+)</a>', r.text)
print('Yout wallet balance:', HTMLParser().unescape(m.groups()[0]))
