#!/usr/bin/env python
from __future__ import print_function
import re
from sys import version_info
from steamweb.steamwebbrowser import SteamWebBrowser
if version_info.major >= 3:
    from html.parser import HTMLParser
else:
    from HTMLParser import HTMLParser

swb = SteamWebBrowser()
if not swb.logged_in():
    swb.login()
r = swb.get('https://store.steampowered.com/account/')
m = re.search(r'<div class="accountData price">(.*) </div>', r.content)
print('Yout wallet balance:', HTMLParser().unescape(m.groups()[0]))
