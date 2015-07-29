# steamweb
Python lib to access/use steam web pages (stuff not exposed via [the API](https://developer.valvesoftware.com/wiki/Steam_Web_API)/[smiley/steamapi](https://github.com/smiley/steamapi))

Installation with pip:
```sh
pip install git+https://github.com/jayme-github/steamweb
```

`SteamWebBrowser` will ask for your Steam credentials when first used.
You may create a config file manually if you whish (`~/.config/SteamWebBrowser/config.cfg`):
```cfg
[steamweb]
username = YOURSTEAMUSERNAME
password = YOURSTEAMPASSWORD
```

Usage like (or see demo):
```python
from steamweb import *
swb = SteamWebBrowserCfg()
if not swb.logged_in():
    swb.login()
if swb.logged_in(): print 'Yay!'
r = swb.get('https://store.steampowered.com/account/')
# r is a requests.Response object

from bs4 import BeautifulSoup
soup = BeautifulSoup(r.content)
print 'Yout wallet balance:', soup.find('div', attrs={'class': 'accountData price'}).get_text()
```
