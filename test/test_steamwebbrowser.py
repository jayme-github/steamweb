import os
import shutil
import unittest
import tempfile

from steamweb import *

class TestSteamWebBrowser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.environ['STEAMWEBROWSER_HOME'] = self.temp_dir
        self.swb = SteamWebBrowser('user', 'password')

    def tearDown(self):
        if os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_appdata_path(self):
        ''' Test if appdata path is created '''
        appdata_path = self.swb.appdata_path
        self.assertTrue(os.path.isdir(appdata_path) and os.access(appdata_path, os.W_OK))
