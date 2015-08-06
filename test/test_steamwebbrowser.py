import os
import shutil
import unittest
import tempfile

from steamweb import *

class TestSteamWebBrowser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.environ['STEAMWEBROWSER_HOME'] = self.temp_dir

    def tearDown(self):
        if os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_appdata_path(self):
        ''' Test if appdata path is created '''
        swb = SteamWebBrowser('user', 'password')
        self.assertTrue(os.path.isdir(swb.appdata_path) and os.access(swb.appdata_path, os.W_OK))

    def test_not_logged_in(self):
        swb = SteamWebBrowser('user', 'password')
        self.assertFalse(swb.logged_in())
