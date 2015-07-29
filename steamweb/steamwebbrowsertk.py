from .steamwebbrowser import SteamWebBrowserCfg
from sys import version_info
from PIL.ImageTk import PhotoImage
if version_info.major >= 3: # Python3
    import tkinter as tk
else: # Python 2
    import Tkinter as tk

class SteamWebBrowserTk(SteamWebBrowserCfg):
    ''' SteamWebBrowserCfg with Tkinter UI for displaying captcha image
    '''
    @staticmethod
    def _handle_captcha(captcha_data, message=''):
        tk_root = tk.Tk()
        def close(captcha_text):
            if captcha_text.get() != '':
                tk_root.destroy() # Faster than .quit() and won't be re-used anyways
        tk_root.title('')
        tk_root.configure(bg='black')
        captcha = PhotoImage(data=captcha_data)
        tk.Label(
                tk_root,
                text=message,
                bg='black',
                fg='white',
        ).pack()
        tk.Label(
                tk_root,
                image=captcha,
                bg='black',
                fg='white',
        ).pack()
        captcha_text = tk.StringVar()
        tk.Entry(
                tk_root,
                textvariable=captcha_text,
                bg='black',
                fg='white',
                insertbackground='white',
        ).pack()
        tk_root.bind('<Return>', lambda s: close(captcha_text))
        tk_root.mainloop()

        return captcha_text.get()
