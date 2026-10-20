# ABYSSCODE

A small Python command-line tool that wraps files in a custom 64-symbol text encoding and encrypts them with AES-256-GCM.

## Run locally

Requires Python 3.10+ and pip.

```powershell
py -m pip install -r requirements.txt
py downloads/abysscode.py keygen --out abyss.key
py downloads/abysscode.py encode secret.txt secret.aby --key-file abyss.key
py downloads/abysscode.py decode secret.aby recovered.txt --key-file abyss.key
```

To use a passphrase instead of a key file, replace `--key-file abyss.key` with `--passphrase` for both encode and decode.

## Host the website

Upload `index.html` and the `downloads/` folder to any static web host (GitHub Pages, Netlify, Cloudflare Pages, or a normal web server). The page is a download/info page; the Python program runs locally on the user's computer, not in the browser.

## Security notes

- The custom alphabet is obfuscation/formatting, not the security boundary.
- AES-256-GCM provides encryption and tamper detection; scrypt derives a key from passphrases.
- Keep the key/passphrase private and backed up. Losing it means encrypted files cannot be recovered.
- Do not use this as a substitute for a security review or a vetted application for high-stakes data.
