#!/usr/bin/env python
from __future__ import print_function
import re
from sys import version_info
from steamweb.steamwebbrowser import SteamWebBrowserCfg
if version_info.major >= 3:
    from html.parser import HTMLParser
else:
    from HTMLParser import HTMLParser

swb = SteamWebBrowserCfg()
if not swb.logged_in():
    swb.login()
r = swb.get('https://store.steampowered.com/account/')
m = re.search(r'<a href="http://store.steampowered.com/account/history/">(\S+) </a>', r.content)
print('Yout wallet balance:', HTMLParser().unescape(m.groups()[0]))
