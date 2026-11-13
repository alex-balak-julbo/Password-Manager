# Vault: a tiny local password manager

PHP 8.1+ · SQLite · Tailwind (CDN) · one user · every field encrypted at rest.

## Requirements
- PHP 8.1 or newer with the `pdo_sqlite` and `sodium` extensions
  (both are on by default in current PHP; in XAMPP/WAMP check `php.ini` for
  `extension=pdo_sqlite` and `extension=sodium`).
- Internet on first load (Tailwind and the font come from a CDN).

## Run it
Easiest, with PHP's built-in server (recommended; keeps everything outside `public/` unreachable):

    cd password-manager
    php -S localhost:8000 -t public

Open http://localhost:8000 and choose a master password.

With Apache (XAMPP/WAMP): put the folder in `www/` or `htdocs/` and open
http://localhost/password-manager/public/ . The included `.htaccess` files block
access to `.env`, `src/` and `storage/`. `AllowOverride` must be enabled
(it is by default in XAMPP). Verify by opening
http://localhost/password-manager/.env : you should get 403.

## How it protects your data
- `.env` is created on first run with a random `APP_KEY` (256-bit).
- Name, website, username, password and notes are each encrypted with
  libsodium `secretbox` (XSalsa20-Poly1305) before going into SQLite.
  Opening `storage/vault.sqlite` shows only ciphertext.
- The master password is stored only as a bcrypt/Argon hash (`password_hash`).
- Login is limited to 5 wrong attempts, then a 5 minute lockout.
- The session auto-locks after 15 minutes idle. Forms are CSRF-protected.
- Passwords are never in the page HTML; they are fetched only when you click
  Copy, Show or Edit. Copied passwords are cleared from the clipboard after 30 s.

## Back up
Keep **both** `.env` and `storage/vault.sqlite`. Without the original `APP_KEY`
the data cannot be decrypted, and the key alone is useless without the database.
Store the backup somewhere other than where the app runs.

## Notes
- If someone has both `.env` and the database file, they can decrypt everything
  (they still don't need your master password). For stronger protection, move
  `.env` out of the project or derive the key from the master password.
- Keyboard: `/` focuses the search box.
