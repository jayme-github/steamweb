.. image:: https://travis-ci.org/jayme-github/steamweb.svg?branch=master
    :target: https://travis-ci.org/jayme-github/steamweb
    :alt: Travis CI
.. image:: https://coveralls.io/repos/jayme-github/steamweb/badge.svg?branch=master&service=github
   :target: https://coveralls.io/github/jayme-github/steamweb?branch=master
   :alt: Coveralls test coverage
.. image:: https://landscape.io/github/jayme-github/steamweb/master/landscape.svg?style=flat
   :target: https://landscape.io/github/jayme-github/steamweb/master
   :alt: Code Health

============
Steamweb
============

`steamweb <https://github.com/jayme-github/steamweb>`_ is a python library to access/use steam web pages (stuff not exposed via `the API, <https://developer.valvesoftware.com/wiki/Steam_Web_API>`_ for the API, use `smiley/steamap <https://github.com/smiley/steamapi>`_)

Installation
============

.. code-block:: sh

    pip install steamweb

Requirements
============

* pycrypto>=2.6.1
* requests>=2.7.0
* future>=0.14.3 (python 2.x)


Usage
=====

.. code-block:: python

    from steamweb import SteamWebBrowser
    swb = SteamWebBrowser('YourSteamUsername', 'YourSteamPassword')
    if not swb.logged_in():
        swb.login()
    if swb.logged_in(): print 'Yay!'
    r = swb.get('https://store.steampowered.com/account/')
    # r is a requests.Response object



There is a subclass *SteamWebBrowserCfg* that includes basic configuration file handling and will ask for your Steam credentials when first used. You may also create a config file manually if you wish (*~/.config/SteamWebBrowser/config.cfg*):

.. code-block:: ini

    [steamweb]
    username = YOURSTEAMUSERNAME
    password = YOURSTEAMPASSWORD

.. code-block:: python

    from steamweb import SteamWebBrowserCfg
    swb = SteamWebBrowserCfg()
    if not swb.logged_in():
        swb.login()
    if swb.logged_in(): print 'Yay!'
    r = swb.get('https://store.steampowered.com/account/')
    # r is a requests.Response object

The subclass *SteamWebBrowserTk* inherits from *SteamWebBrowserCfg* (so it has configfile support too) and provides a simple Tkinter UI for presenting captcha images to the user.

Implementations
===============

- `Idle Steam <https://github.com/jayme-github/steam_idle>`_ makes heavy use of steamweb.
