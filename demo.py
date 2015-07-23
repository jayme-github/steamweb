#!/usr/bin/env python

from steamweb.steamwebbrowser import SteamWebBrowser
from bs4 import BeautifulSoup

swb = SteamWebBrowser()
if not swb.logged_in():
    swb.login()
r = swb.get('https://store.steampowered.com/account/')
soup = BeautifulSoup(r.content, 'html.parser')
print 'Yout wallet balance:', soup.find('div', attrs={'class': 'accountData price'}).get_text()
