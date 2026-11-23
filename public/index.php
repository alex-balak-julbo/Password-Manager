<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';
set_exception_handler(function (Throwable $e): void {
    http_response_code(500);
    echo '<!doctype html><meta charset="utf-8"><title>Error</title>'
       . '<body style="font-family:system-ui;max-width:60rem;margin:2rem auto;padding:0 1rem">'
       . '<h1>Something went wrong</h1>'
       . '<p><strong>Type:</strong> ' . h(get_class($e)) . '</p>'
       . '<p><strong>Message:</strong> ' . h($e->getMessage()) . '</p>'
       . '<p><strong>Location:</strong> ' . h($e->getFile()) . ' on line <strong>' . $e->getLine() . '</strong></p>'
       . '<h2>Stack Trace</h2>'
       . '<pre style="background:#f4f4f4;padding:1rem;overflow-x:auto;border-radius:4px">'
       . h($e->getTraceAsString())
       . '</pre></body>';
});

$error     = null;
$hasMaster = meta_get('master_hash') !== null;
$authType  = meta_get('master_type') ?? 'password';
$action    = (string) ($_POST['action'] ?? $_GET['action'] ?? '');
$isPost    = $_SERVER['REQUEST_METHOD'] === 'POST';

// ======================================================================
// Setup and login (no session needed)
// ======================================================================
if ($isPost && $action === 'setup' && !$hasMaster) {
    check_csrf();
    $authType = (string) ($_POST['credential_type'] ?? 'password');
    $credential = (string) ($_POST['credential'] ?? '');
    $confirmation = (string) ($_POST['confirm'] ?? '');
    if (!in_array($authType, ['password', 'code'], true)) {
        $error = 'Choose a valid unlock method.';
        $authType = 'password';
    } elseif ($authType === 'code' && !preg_match('/\A[0-9]{6}\z/', $credential)) {
        $error = 'The code must contain exactly 6 digits.';
    } elseif ($authType === 'password' && strlen($credential) < 10) {
        $error = 'Use at least 10 characters.';
    } elseif (!hash_equals($credential, $confirmation)) {
        $error = 'The two values don\'t match.';
    } else {
        meta_set('master_hash', password_hash($credential, PASSWORD_DEFAULT));
        meta_set('master_type', $authType);
        login_session();
        redirect();
    }
}

if ($isPost && $action === 'login' && $hasMaster) {
    check_csrf();
    $left = max(0, (int) meta_get('locked_until') - time());
    if ($left > 0) {
        $error = 'Too many attempts. Try again in ' . (int) ceil($left / 60) . ' min.';
    } elseif (password_verify((string) ($_POST['credential'] ?? $_POST['password'] ?? ''), (string) meta_get('master_hash'))) {
        meta_set('failed', '0');
        login_session();
        redirect();
    } else {
        usleep(600000); // slow down guessing
        $failed = (int) meta_get('failed') + 1;
        if ($failed >= 5) {
            meta_set('locked_until', (string) (time() + 300));
            $failed = 0;
        }
        meta_set('failed', (string) $failed);
        $error = 'Wrong master password.';
    }
}

// ======================================================================
// Login / setup screen
// ======================================================================
if (!is_authed()) {
    $setupMode = !$hasMaster;
    $selectedType = $setupMode
        ? ((($_POST['credential_type'] ?? 'password') === 'code') ? 'code' : 'password')
        : $authType;
    $codeMode = $selectedType === 'code';
    ?>
<!doctype html>
<html lang="en">
<head>
<?php require __DIR__ . '/../src/head.php'; ?>
<title><?= $setupMode ? 'Set up' : 'Unlock' ?> · Vault</title>
</head>
<body class="min-h-screen bg-mist text-ink font-sans antialiased flex items-center justify-center p-4">
  <main class="w-full max-w-sm">
    <h1 class="text-3xl font-bold tracking-tight">Vault</h1>
    <p class="mt-1 text-slate2">
      <?= $setupMode ? 'Choose how you want to unlock the vault.' : 'Enter your unlock credential.' ?>
    </p>

    <form method="post" id="authForm" data-auth-type="<?= h($selectedType) ?>" class="mt-6 space-y-4 bg-white border border-line rounded-lg p-6">
      <input type="hidden" name="csrf" value="<?= h(csrf()) ?>">
      <input type="hidden" name="action" value="<?= $setupMode ? 'setup' : 'login' ?>">

      <?php if ($error): ?>
        <p role="alert" class="text-sm text-brick bg-brick/10 rounded px-3 py-2"><?= h($error) ?></p>
      <?php endif; ?>

      <?php if ($setupMode): ?>
        <label class="block">
          <span class="text-sm font-medium">Unlock method</span>
          <select id="authType" name="credential_type"
                  class="mt-1 w-full rounded border border-line px-3 py-2 focus:outline-none focus:ring-2 focus:ring-pine">
            <option value="password" <?= $selectedType === 'password' ? 'selected' : '' ?>>Master password</option>
            <option value="code" <?= $selectedType === 'code' ? 'selected' : '' ?>>6-digit code</option>
          </select>
        </label>
      <?php endif; ?>

      <label class="block">
        <span id="credentialLabel" class="text-sm font-medium"><?= $codeMode ? '6-digit code' : 'Master password' ?></span>
        <input id="credential" type="password" name="credential" required autofocus
               autocomplete="<?= $setupMode ? 'new-password' : 'current-password' ?>"
               class="mt-1 w-full rounded border border-line px-3 py-2 focus:outline-none focus:ring-2 focus:ring-pine">
      </label>

      <?php if ($setupMode): ?>
        <label class="block">
          <span id="confirmLabel" class="text-sm font-medium"><?= $codeMode ? 'Repeat 6-digit code' : 'Repeat master password' ?></span>
          <input id="confirm" type="password" name="confirm" required autocomplete="new-password"
                 class="mt-1 w-full rounded border border-line px-3 py-2 focus:outline-none focus:ring-2 focus:ring-pine">
        </label>
        <p id="credentialHelp" class="text-sm text-slate2"><?= $codeMode ? 'Exactly 6 digits. A code is quicker but easier to guess than a strong password.' : 'At least 10 characters. A few random words works well.' ?></p>
      <?php endif; ?>

      <button class="w-full rounded bg-pine hover:bg-pine-dark text-white font-semibold py-2.5 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-pine">
        <?= $setupMode ? 'Create vault' : 'Unlock' ?>
      </button>
    </form>
  </main>
  <script>
    const typeSelect = document.querySelector('#authType');
    const authForm = document.querySelector('#authForm');
    const credential = document.querySelector('#credential');
    const confirmCredential = document.querySelector('#confirm');
    function updateCredentialFields() {
      const codeMode = (typeSelect ? typeSelect.value : authForm.dataset.authType) === 'code';
      document.querySelector('#credentialLabel').textContent = codeMode ? '6-digit code' : 'Master password';
      credential.inputMode = codeMode ? 'numeric' : 'text';
      if (codeMode) {
        credential.maxLength = 6;
        credential.pattern = '[0-9]{6}';
      } else {
        credential.removeAttribute('maxlength');
        credential.removeAttribute('pattern');
      }
      if (confirmCredential) {
        document.querySelector('#confirmLabel').textContent = codeMode ? 'Repeat 6-digit code' : 'Repeat master password';
        confirmCredential.inputMode = codeMode ? 'numeric' : 'text';
        if (codeMode) {
          confirmCredential.maxLength = 6;
          confirmCredential.pattern = '[0-9]{6}';
        } else {
          confirmCredential.removeAttribute('maxlength');
          confirmCredential.removeAttribute('pattern');
        }
        document.querySelector('#credentialHelp').textContent = codeMode
          ? 'Exactly 6 digits. A code is quicker but easier to guess than a strong password.'
          : 'At least 10 characters. A few random words works well.';
      }
    }
    if (typeSelect) typeSelect.addEventListener('change', updateCredentialFields);
    updateCredentialFields();
  </script>
</body>
</html>
<?php
    exit;
}

// ======================================================================
// Authenticated actions
// ======================================================================
if ($isPost) {
    check_csrf();

    if ($action === 'logout') {
        logout();
        redirect();
    }

    // Keep-alive from the browser while the user is active (session timestamp is refreshed in bootstrap)
    if ($action === 'ping') {
        http_response_code(204);
        exit;
    }

    // JSON: fetch one decrypted entry (used by copy / show / edit)
    if ($action === 'get') {
        header('Content-Type: application/json');
        $st = db()->prepare('SELECT * FROM entries WHERE id = ?');
        $st->execute([(int) ($_POST['id'] ?? 0)]);
        $r = $st->fetch();
        if (!$r) {
            http_response_code(404);
            echo json_encode(['error' => 'Not found']);
            exit;
        }
        echo json_encode([
            'id'       => (int) $r['id'],
            'name'     => decrypt($r['name']),
            'url'      => decrypt($r['url']),
            'username' => decrypt($r['username']),
            'password' => decrypt($r['password']),
            'notes'    => decrypt($r['notes']),
        ]);
        exit;
    }

    if ($action === 'save') {
        $id       = (int) ($_POST['entry_id'] ?? 0);
        $name     = trim((string) ($_POST['name'] ?? ''));
        $url      = trim((string) ($_POST['url'] ?? ''));
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $notes    = (string) ($_POST['notes'] ?? '');

        if ($name === '') {
            flash('error', 'Give the entry a name so you can find it later.');
            redirect();
        }

        $now  = gmdate('c');
        $vals = [encrypt($name), encrypt($url), encrypt($username), encrypt($password), encrypt($notes)];

        if ($id > 0) {
            db()->prepare('UPDATE entries SET name=?, url=?, username=?, password=?, notes=?, updated_at=? WHERE id=?')
                ->execute([...$vals, $now, $id]);
            flash('ok', 'Saved changes to ' . $name . '.');
        } else {
            db()->prepare('INSERT INTO entries (name, url, username, password, notes, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)')
                ->execute([...$vals, $now, $now]);
            flash('ok', 'Added ' . $name . '.');
        }
        redirect();
    }

    if ($action === 'delete') {
        db()->prepare('DELETE FROM entries WHERE id = ?')->execute([(int) ($_POST['entry_id'] ?? 0)]);
        flash('ok', 'Entry deleted.');
        redirect();
    }
}

// ======================================================================
// Vault view
// ======================================================================
$items = [];
foreach (db()->query('SELECT id, name, url, username FROM entries')->fetchAll() as $r) {
    $items[] = [
        'id'       => (int) $r['id'],
        'name'     => decrypt($r['name']),
        'url'      => decrypt($r['url']),
        'username' => decrypt($r['username']),
    ];
}
usort($items, fn ($a, $b) => strcasecmp($a['name'], $b['name']));

$idle      = idle_timeout();
$idleLabel = $idle % 60 === 0 ? ($idle / 60) . ' min' : $idle . ' s';

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?>
<!doctype html>
<html lang="en">
<head>
<?php require __DIR__ . '/../src/head.php'; ?>
<title>Vault</title>
</head>
<body class="min-h-screen bg-mist text-ink font-sans antialiased">
<div class="max-w-3xl mx-auto px-4 py-8">

  <header class="flex items-center justify-between">
    <h1 class="text-2xl font-bold tracking-tight">Vault</h1>
    <form method="post" id="logoutForm">
      <input type="hidden" name="csrf" value="<?= h(csrf()) ?>">
      <input type="hidden" name="action" value="logout">
      <button title="Lock (Ctrl+L)" class="text-sm font-medium text-slate2 hover:text-ink rounded px-3 py-1.5 border border-line bg-white focus:outline-none focus:ring-2 focus:ring-pine">Lock</button>
    </form>
  </header>

  <?php if ($flash): ?>
    <p role="status" class="mt-4 text-sm rounded px-3 py-2 <?= $flash[0] === 'error' ? 'text-brick bg-brick/10' : 'text-pine-dark bg-pine/10' ?>">
      <?= h($flash[1]) ?>
    </p>
  <?php endif; ?>

  <div class="mt-6 flex gap-3">
    <input id="search" type="search" placeholder="Search by name, website or username  ( / )" autocomplete="off"
           class="flex-1 min-w-0 rounded-lg border border-line bg-white px-4 py-3 text-lg focus:outline-none focus:ring-2 focus:ring-pine">
    <button id="addBtn" class="shrink-0 rounded-lg bg-pine hover:bg-pine-dark text-white font-semibold px-5 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-pine">
      Add entry
    </button>
  </div>

  <?php if (!$items): ?>
    <div class="mt-6 bg-white border border-line rounded-lg p-8 text-center">
      <p class="font-semibold">Your vault is empty</p>
      <p class="text-slate2 mt-1">Add your first login to see it here.</p>
    </div>
  <?php else: ?>
    <ul id="list" class="mt-6 bg-white border border-line rounded-lg divide-y divide-line">
      <?php foreach ($items as $it): ?>
        <li class="entry p-4 flex flex-col gap-3 sm:flex-row sm:items-center"
            data-id="<?= $it['id'] ?>"
            data-name="<?= h($it['name']) ?>"
            data-username="<?= h($it['username']) ?>"
            data-search="<?= h(mb_strtolower($it['name'] . ' ' . $it['url'] . ' ' . $it['username'])) ?>">
          <div class="min-w-0 flex-1">
            <p class="font-semibold truncate"><?= h($it['name']) ?></p>
            <?php if ($it['url'] !== ''): ?>
              <a href="<?= h(href_for($it['url'])) ?>" target="_blank" rel="noopener noreferrer"
                 class="block text-sm text-pine hover:underline truncate"><?= h($it['url']) ?></a>
            <?php endif; ?>
            <?php if ($it['username'] !== ''): ?>
              <p class="text-sm text-slate2 truncate"><?= h($it['username']) ?></p>
            <?php endif; ?>
            <p class="pw hidden mt-1 font-mono text-sm break-all bg-mist rounded px-2 py-1"></p>
          </div>
          <div class="flex flex-wrap gap-2 text-sm">
            <?php if ($it['username'] !== ''): ?>
              <button data-act="copy-user" class="btn">Copy user</button>
            <?php endif; ?>
            <button data-act="copy-pass" class="btn btn-primary">Copy password</button>
            <button data-act="show" class="btn">Show</button>
            <button data-act="edit" class="btn">Edit</button>
            <button data-act="delete" class="btn btn-danger">Delete</button>
          </div>
        </li>
      <?php endforeach; ?>
    </ul>
    <p id="noMatch" class="hidden mt-6 text-center text-slate2">Nothing matches that search.</p>
  <?php endif; ?>

  <p class="mt-6 text-xs text-slate2 text-center">
    <?= count($items) ?> <?= count($items) === 1 ? 'entry' : 'entries' ?> · auto-locks after <?= h($idleLabel) ?> idle · Ctrl+L to lock now
  </p>
</div>

<!-- Add / edit dialog -->
<dialog id="dlg" class="rounded-lg p-0 w-[calc(100%-2rem)] max-w-lg backdrop:bg-ink/50">
  <form id="entryForm" method="post" class="p-6 space-y-4">
    <input type="hidden" name="csrf" value="<?= h(csrf()) ?>">
    <input type="hidden" name="action" value="save">
    <input type="hidden" name="entry_id" value="">

    <h2 id="dlgTitle" class="text-xl font-bold">Add entry</h2>

    <label class="block">
      <span class="text-sm font-medium">Name</span>
      <input name="name" required maxlength="200" autocomplete="off" placeholder="e.g. Netflix"
             class="mt-1 w-full rounded border border-line px-3 py-2 focus:outline-none focus:ring-2 focus:ring-pine">
    </label>

    <label class="block">
      <span class="text-sm font-medium">Website</span>
      <input name="url" maxlength="500" autocomplete="off" placeholder="https://netflix.com"
             class="mt-1 w-full rounded border border-line px-3 py-2 focus:outline-none focus:ring-2 focus:ring-pine">
    </label>

    <label class="block">
      <span class="text-sm font-medium">Username or email</span>
      <input name="username" maxlength="300" autocomplete="off"
             class="mt-1 w-full rounded border border-line px-3 py-2 focus:outline-none focus:ring-2 focus:ring-pine">
    </label>

    <div>
      <label for="pwField" class="text-sm font-medium">Password</label>
      <div class="mt-1 flex gap-2">
        <input id="pwField" name="password" type="password" maxlength="500" autocomplete="new-password"
               class="flex-1 min-w-0 rounded border border-line px-3 py-2 font-mono focus:outline-none focus:ring-2 focus:ring-pine">
        <button type="button" id="pwToggle" class="btn">Show</button>
        <button type="button" id="pwGen" class="btn">Generate</button>
      </div>
    </div>

    <label class="block">
      <span class="text-sm font-medium">Notes <span class="text-slate2 font-normal">(optional)</span></span>
      <textarea name="notes" rows="3" maxlength="2000"
                class="mt-1 w-full rounded border border-line px-3 py-2 focus:outline-none focus:ring-2 focus:ring-pine"></textarea>
    </label>

    <div class="flex justify-end gap-2 pt-2">
      <button type="button" id="dlgCancel" class="btn">Cancel</button>
      <button class="btn btn-primary">Save entry</button>
    </div>
  </form>
</dialog>

<form id="deleteForm" method="post" class="hidden">
  <input type="hidden" name="csrf" value="<?= h(csrf()) ?>">
  <input type="hidden" name="action" value="delete">
  <input type="hidden" name="entry_id" value="">
</form>

<div id="toast" role="status" aria-live="polite"
     class="fixed bottom-6 left-1/2 -translate-x-1/2 bg-ink text-white text-sm rounded px-4 py-2 opacity-0 transition-opacity pointer-events-none"></div>

<script>
const CSRF = <?= json_encode(csrf()) ?>;
const $  = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

// ---- toast + clipboard ------------------------------------------------
let toastTimer, clipTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.remove('opacity-0');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('opacity-0'), 2200);
}
async function copy(text, label, sensitive = false) {
  try {
    await navigator.clipboard.writeText(text);
    toast(sensitive ? label + ' copied (clears in 30s)' : label + ' copied');
    clearTimeout(clipTimer);
    if (sensitive) clipTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000);
  } catch (e) {
    toast('Could not copy. Use http://localhost or https.');
  }
}

// ---- fetch one decrypted entry ---------------------------------------
async function getEntry(id) {
  const res = await fetch('?action=get', {
    method: 'POST',
    headers: { 'X-CSRF-Token': CSRF, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ action: 'get', id }),
  });
  if (!res.ok) throw new Error('Could not load entry');
  return res.json();
}

// ---- search -----------------------------------------------------------
const search = $('#search');
search.addEventListener('input', () => {
  const terms = search.value.toLowerCase().split(/\s+/).filter(Boolean);
  let shown = 0;
  $$('.entry').forEach(li => {
    const ok = terms.every(t => li.dataset.search.includes(t));
    li.classList.toggle('hidden', !ok);
    if (ok) shown++;
  });
  const nm = $('#noMatch');
  if (nm) nm.classList.toggle('hidden', shown > 0 || !terms.length);
});
document.addEventListener('keydown', e => {
  const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName);
  if (e.key === '/' && !typing && !$('#dlg').open) { e.preventDefault(); search.focus(); }
  if (e.key === 'Escape' && document.activeElement === search) { search.value = ''; search.dispatchEvent(new Event('input')); }
});

// ---- list actions -----------------------------------------------------
document.addEventListener('click', async e => {
  const btn = e.target.closest('[data-act]');
  if (!btn) return;
  const li = btn.closest('.entry');
  const id = li.dataset.id;
  try {
    switch (btn.dataset.act) {
      case 'copy-user':
        copy(li.dataset.username, 'Username');
        break;
      case 'copy-pass':
        copy((await getEntry(id)).password, 'Password', true);
        break;
      case 'show': {
        const out = $('.pw', li);
        if (!out.classList.contains('hidden')) { hidePw(li); break; }
        out.textContent = (await getEntry(id)).password || '(empty)';
        out.classList.remove('hidden');
        btn.textContent = 'Hide';
        li._timer = setTimeout(() => hidePw(li), 10000);
        break;
      }
      case 'edit':
        openDialog(await getEntry(id));
        break;
      case 'delete':
        if (confirm('Delete "' + li.dataset.name + '"? This cannot be undone.')) {
          $('#deleteForm [name=entry_id]').value = id;
          $('#deleteForm').submit();
        }
        break;
    }
  } catch (err) {
    toast(err.message);
  }
});
function hidePw(li) {
  clearTimeout(li._timer);
  const out = $('.pw', li);
  out.textContent = '';
  out.classList.add('hidden');
  $('[data-act=show]', li).textContent = 'Show';
}

// ---- add / edit dialog ------------------------------------------------
const dlg = $('#dlg'), form = $('#entryForm'), pw = $('#pwField');
function openDialog(entry) {
  form.reset();
  pw.type = 'password';
  $('#pwToggle').textContent = 'Show';
  const f = form.elements;
  f.entry_id.value = entry ? entry.id : '';
  if (entry) {
    f.name.value = entry.name; f.url.value = entry.url; f.username.value = entry.username;
    f.password.value = entry.password; f.notes.value = entry.notes;
  }
  $('#dlgTitle').textContent = entry ? 'Edit entry' : 'Add entry';
  dlg.showModal();
  f.name.focus();
}
$('#addBtn').addEventListener('click', () => openDialog(null));
$('#dlgCancel').addEventListener('click', () => dlg.close());
dlg.addEventListener('click', e => { if (e.target === dlg) dlg.close(); });

$('#pwToggle').addEventListener('click', e => {
  pw.type = pw.type === 'password' ? 'text' : 'password';
  e.target.textContent = pw.type === 'password' ? 'Show' : 'Hide';
});
$('#pwGen').addEventListener('click', () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+?';
  const max = Math.floor(0x100000000 / chars.length) * chars.length; // avoid modulo bias
  let out = '';
  while (out.length < 20) {
    const [n] = crypto.getRandomValues(new Uint32Array(1));
    if (n < max) out += chars[n % chars.length];
  }
  pw.value = out;
  pw.type = 'text';
  $('#pwToggle').textContent = 'Hide';
});

// ---- lock: Ctrl+L and idle timeout ---------------------------------------
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'l') {
    e.preventDefault();
    $('#logoutForm').submit();
  }
});

const IDLE_MS = <?= $idle * 1000 ?>;
let idleTimer, lastPing = Date.now();
function activity() {
  clearTimeout(idleTimer);
  // reload slightly after the server-side limit so the server shows the unlock screen
  idleTimer = setTimeout(() => location.reload(), IDLE_MS + 1500);
  if (Date.now() - lastPing > 5000) {          // tell the server we're still here
    lastPing = Date.now();
    fetch('?action=ping', {
      method: 'POST',
      headers: { 'X-CSRF-Token': CSRF, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ action: 'ping' }),
    }).then(r => { if (!r.ok) location.reload(); }).catch(() => {});
  }
}
['click', 'keydown', 'mousemove', 'touchstart'].forEach(ev =>
  document.addEventListener(ev, activity, { passive: true }));
activity();
</script>
</body>
</html>
