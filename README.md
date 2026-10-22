# ABYSSCODE

A browser-based ABYSSCODE encoder/decoder, compatible with the Python CLI's **key-file mode**.

## Run locally
Open `index.html` in a modern browser. For best results, use a local static server or GitHub Pages (Web Crypto requires a secure context; `localhost` is considered secure).

## Publish on GitHub Pages
1. Put `index.html` in the repository root.
2. Commit and push it to `main`.
3. In **Settings → Pages**, select **Deploy from a branch**, branch `main`, folder `/(root)`.
4. Open the published Pages URL after deployment.

GitHub Pages hosts static HTML and JavaScript, so no Python server is needed.

## Use
- Generate a key in the page and download `abyss.key`, or generate one with the Python CLI: `py downloads/abysscode.py keygen --out abyss.key`.
- Paste the key file's 64 hexadecimal characters into the key field.
- Select Encode or Decode.

## Compatibility and security notes
- Browser and Python key-file mode use AES-256-GCM and the same binary container and custom alphabet.
- The browser does not support passphrase mode in this version.
- Encoding is a representation; encryption is what protects the message.
- Keep keys private. Anyone with the key can decrypt messages.
- This project is an educational custom format built on established cryptography, not a new cryptographic primitive.
