<?php
declare(strict_types=1);

/**
 * Bootstrap: env, encryption, database, session, CSRF.
 */

define('ROOT', dirname(__DIR__));

// ---------------------------------------------------------------- .env
$envPath = ROOT . '/.env';
if (!is_file($envPath)) {
    // First run: generate a random 256-bit encryption key.
    $newKey = base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
    file_put_contents($envPath, "APP_KEY=\"{$newKey}\"\n");
    @chmod($envPath, 0600);
}

function env(string $name): ?string
{
    static $vars = null;
    if ($vars === null) {
        $vars = [];
        foreach (file(ROOT . '/.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || !str_contains($line, '=')) {
                continue;
            }
            [$k, $v] = explode('=', $line, 2);
            $vars[trim($k)] = trim(trim($v), "\"'");
        }
    }
    return $vars[$name] ?? null;
}

// ---------------------------------------------------------- encryption
function app_key(): string
{
    static $key = null;
    if ($key === null) {
        $key = base64_decode((string) env('APP_KEY'), true);
        if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new RuntimeException('APP_KEY in .env is missing or invalid (must be 32 bytes, base64).');
        }
    }
    return $key;
}

function encrypt(string $plain): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, app_key()));
}

function decrypt(string $blob): string
{
    $raw = base64_decode($blob, true);
    $min = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;
    if ($raw === false || strlen($raw) < $min) {
        throw new RuntimeException('A stored value is corrupted.');
    }
    $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, app_key());
    if ($plain === false) {
        throw new RuntimeException('Could not decrypt. Is APP_KEY in .env the same key the data was saved with?');
    }
    return $plain;
}

// ------------------------------------------------------------ database
function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $dir = ROOT . '/storage';
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $pdo = new PDO('sqlite:' . $dir . '/vault.sqlite', null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $pdo->exec('CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )');
        // Every text column in "entries" holds encrypted data (base64 of nonce + ciphertext).
        $pdo->exec("CREATE TABLE IF NOT EXISTS entries (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            url        TEXT NOT NULL DEFAULT '',
            username   TEXT NOT NULL DEFAULT '',
            password   TEXT NOT NULL DEFAULT '',
            notes      TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )");
    }
    return $pdo;
}

function meta_get(string $key): ?string
{
    $st = db()->prepare('SELECT value FROM meta WHERE key = ?');
    $st->execute([$key]);
    $v = $st->fetchColumn();
    return $v === false ? null : (string) $v;
}

function meta_set(string $key, string $value): void
{
    db()->prepare('INSERT INTO meta (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value')
        ->execute([$key, $value]);
}

// ------------------------------------------------------------- session
/** Seconds of inactivity before auto-lock. Set IDLE_TIMEOUT in .env (default 60, minimum 10). */
function idle_timeout(): int
{
    $v = env('IDLE_TIMEOUT');
    return ($v !== null && ctype_digit($v)) ? max(10, (int) $v) : 60;
}

function logout(): void
{
    $_SESSION = [];
    session_regenerate_id(true);
}

function is_authed(): bool
{
    return !empty($_SESSION['auth']);
}

function login_session(): void
{
    session_regenerate_id(true);
    $_SESSION['auth'] = true;
    $_SESSION['last'] = time();
}

session_name('pm_session');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Strict',
    'secure'   => !empty($_SERVER['HTTPS']),
]);
session_start();

if (is_authed()) {
    if (time() - (int) ($_SESSION['last'] ?? 0) > idle_timeout()) {
        logout();
    } else {
        $_SESSION['last'] = time();
    }
}

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

// ---------------------------------------------------------------- CSRF
function csrf(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function check_csrf(): void
{
    $sent = $_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($sent) || !hash_equals(csrf(), $sent)) {
        http_response_code(419);
        exit('Invalid or expired form. Go back, reload the page and try again.');
    }
}

// ------------------------------------------------------------- helpers
function h(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function flash(string $type, string $msg): void
{
    $_SESSION['flash'] = [$type, $msg];
}

function redirect(string $to = './'): never
{
    header('Location: ' . $to);
    exit;
}

function href_for(string $url): string
{
    return preg_match('#^https?://#i', $url) ? $url : 'https://' . $url;
}
