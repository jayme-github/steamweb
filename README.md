# steamweb
Python lib to access/use steam web pages (stuff not exposed via [the API](https://developer.valvesoftware.com/wiki/Steam_Web_API), you may use [smiley/steamapi](https://github.com/smiley/steamapi) for that)

Installation with pip:
```sh
pip install git+https://github.com/jayme-github/steamweb
```

`SteamWebBrowser` class provides a way to login to Steam web services (login and send authenticated HTTP GET/PUT requests).
```python
from steamweb import SteamWebBrowser
swb = SteamWebBrowser('YourSteamUsername', 'YourSteamPassword')
if not swb.logged_in():
    swb.login()
if swb.logged_in(): print 'Yay!'
r = swb.get('https://store.steampowered.com/account/')
# r is a requests.Response object
```

There is a subclass `SteamWebBrowserCfg` that includes basic configuration file handling and will ask for your Steam credentials when first used. You may also create a config file manually if you whish (`~/.config/SteamWebBrowser/config.cfg`):
```cfg
[steamweb]
username = YOURSTEAMUSERNAME
password = YOURSTEAMPASSWORD
```

```python
from steamweb import SteamWebBrowserCfg
swb = SteamWebBrowserCfg()
if not swb.logged_in():
    swb.login()
if swb.logged_in(): print 'Yay!'
r = swb.get('https://store.steampowered.com/account/')
# r is a requests.Response object
```

The subclass `SteamWebBrowserTk` provides inherits from `SteamWebBrowserCfg` (so it has configfile support too) and provides a simple Tkinter UI for presenting captcha images to the user.
