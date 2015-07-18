# steamweb
Python lib to access/use steam web pages (stuff not exposed via API

Create a file `config.cfg` like
```cfg
[steamweb]
username = YOURSTEAMUSERNAME
password = YOURSTEAMPASSWORD
```



Usage like:
```python
from steam_login import SteamWebBrowser
swb = SteamWebBrowser()
if not swb.logged_in():
    swb.login()
if swb.logged_in(): print 'Yay!'
r = swb.get('https://store.steampowered.com/account/')
# r is a requests.Response object

from bs4 import BeautifulSoup
soup = BeautifulSoup(r.content)
print 'Yout wallet balance:', soup.find('div', attrs={'class': 'accountData price'}).get_text()
```
