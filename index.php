<?php
/* EMBERENCE DIGITAL: admin panel (login + quote requests + reviews) */
require __DIR__ . '/../includes/bootstrap.php';

session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Strict',
    'secure'   => !empty($_SERVER['HTTPS']),
]);
session_start();

header('X-Robots-Tag: noindex, nofollow');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

const STATUSES = ['New', 'In progress', 'Replied', 'Won', 'Lost'];

function e($s): string { return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function csrf(): string { return $_SESSION['csrf'] ??= bin2hex(random_bytes(32)); }
function csrf_ok(): bool { return isset($_POST['csrf']) && hash_equals(csrf(), (string) $_POST['csrf']); }
function back(string $qs = '') { header('Location: index.php' . $qs); exit; }
function when(string $utc): string {
    return (new DateTime($utc . ' UTC'))->setTimezone(new DateTimeZone(TIMEZONE))->format('d M Y, g:i a');
}
function stars(int $n): string { $n = max(0, min(5, $n)); return str_repeat('★', $n) . str_repeat('☆', 5 - $n); }

/* Full public address of a review link */
function link_url(string $token): string {
    if (SITE_URL !== '') {
        $base = rtrim(SITE_URL, '/');
    } else {
        $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        $dir = rtrim(str_replace('\\', '/', dirname(dirname($_SERVER['SCRIPT_NAME'] ?? '/'))), '/');
        $base = ($https ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? 'localhost') . $dir;
    }
    return $base . '/review.html?t=' . $token;
}

/* [label, css class] for a link row (needs review_id from the LEFT JOIN) */
function link_state(array $l): array {
    if ($l['status'] === 'revoked') return ['Revoked', 'off'];
    if ($l['review_id']) return ['Used', ''];
    if ($l['expires_at'] < gmdate('Y-m-d H:i:s')) return ['Expired', 'off'];
    return ['Active', 'ok'];
}
const STATE_NOTES = [
    'Active'  => 'Waiting for the client. Send them this link.',
    'Used'    => 'Review submitted. The client can still edit or delete it with this link.',
    'Expired' => 'Not used in time. Regenerate to get a fresh link.',
    'Revoked' => 'This link is switched off. Regenerate to turn it on again with a new link.',
];

$pdo = db();
$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$error = '';
$passwordUnchanged = ADMIN_PASSWORD === 'change-this-password-now';

/* ---------- Actions (all POST) ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'login') {
        $pdo->prepare('DELETE FROM login_attempts WHERE created_at < ?')->execute([gmdate('Y-m-d H:i:s', time() - 900)]);
        $st = $pdo->prepare('SELECT COUNT(*) FROM login_attempts WHERE ip = ?');
        $st->execute([$ip]);

        if ($passwordUnchanged) {
            $error = 'Set a new ADMIN_PASSWORD in includes/bootstrap.php before logging in.';
        } elseif ((int) $st->fetchColumn() >= 8) {
            $error = 'Too many attempts. Please wait 15 minutes and try again.';
        } elseif (hash_equals(ADMIN_USER, (string) ($_POST['username'] ?? ''))
               && hash_equals(ADMIN_PASSWORD, (string) ($_POST['password'] ?? ''))) {
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            back();
        } else {
            $pdo->prepare('INSERT INTO login_attempts (ip, created_at) VALUES (?, ?)')->execute([$ip, gmdate('Y-m-d H:i:s')]);
            sleep(1);
            $error = 'Incorrect username or password.';
        }
    } elseif (!empty($_SESSION['admin']) && csrf_ok()) {
        $id = (int) ($_POST['id'] ?? 0);
        $now = gmdate('Y-m-d H:i:s');
        $keep = array_intersect_key($_GET, ['tab' => 1, 'status' => 1, 'q' => 1]);
        $stay = $keep ? '?' . http_build_query($keep) : '';

        if ($action === 'logout') {
            $_SESSION = [];
            session_destroy();
            back();

        /* --- quote requests --- */
        } elseif ($action === 'status' && in_array($_POST['status'] ?? '', STATUSES, true)) {
            $pdo->prepare('UPDATE quotes SET status = ? WHERE id = ?')->execute([$_POST['status'], $id]);
        } elseif ($action === 'delete') {
            $pdo->prepare('DELETE FROM quotes WHERE id = ?')->execute([$id]);

        /* --- review links --- */
        } elseif ($action === 'link_create') {
            $name = cap_text((string) ($_POST['client_name'] ?? ''), 100);
            $handle = cap_text((string) ($_POST['handle'] ?? ''), 60);
            $quoteId = (int) ($_POST['quote_id'] ?? 0);

            if ($quoteId) {
                /* One link per quote request: reuse it if it already exists */
                $st = $pdo->prepare('SELECT id FROM review_links WHERE quote_id = ?');
                $st->execute([$quoteId]);
                if ($existing = (int) $st->fetchColumn()) back('?tab=reviews&open=l' . $existing . '#l' . $existing);
                $st = $pdo->prepare('SELECT name FROM quotes WHERE id = ?');
                $st->execute([$quoteId]);
                $name = (string) $st->fetchColumn();
            }
            if ($name === '') {
                $_SESSION['flash'] = 'Enter a client name to generate a link.';
                back('?tab=reviews');
            }
            $pdo->prepare('INSERT INTO review_links (token, client_name, handle, quote_id, status, created_at, expires_at) VALUES (?,?,?,?,?,?,?)')
                ->execute([new_token(), $name, $handle, $quoteId ?: null, 'active', $now, gmdate('Y-m-d H:i:s', time() + REVIEW_LINK_DAYS * 86400)]);
            $newId = (int) $pdo->lastInsertId();
            back('?tab=reviews&open=l' . $newId . '#l' . $newId);
        } elseif ($action === 'link_revoke') {
            $pdo->prepare("UPDATE review_links SET status = 'revoked' WHERE id = ?")->execute([$id]);
            back('?tab=reviews&open=l' . $id . '#l' . $id);
        } elseif ($action === 'link_regen') {
            $pdo->prepare("UPDATE review_links SET token = ?, status = 'active', expires_at = ? WHERE id = ?")
                ->execute([new_token(), gmdate('Y-m-d H:i:s', time() + REVIEW_LINK_DAYS * 86400), $id]);
            back('?tab=reviews&open=l' . $id . '#l' . $id);

        /* --- reviews --- */
        } elseif ($action === 'review_visibility') {
            $to = ($_POST['to'] ?? '') === 'hidden' ? 'hidden' : 'published';
            $pdo->prepare('UPDATE reviews SET status = ? WHERE id = ?')->execute([$to, $id]);
            back('?tab=reviews&open=r' . $id . '#r' . $id);
        } elseif ($action === 'review_delete') {
            $pdo->prepare('DELETE FROM reviews WHERE id = ?')->execute([$id]);
            back('?tab=reviews');
        } elseif ($action === 'review_save') {
            $st = $pdo->prepare('SELECT * FROM reviews WHERE id = ?');
            $st->execute([$id]);
            if ($old = $st->fetch()) {
                $name = cap_text((string) ($_POST['display_name'] ?? ''), 60);
                $title = cap_text((string) ($_POST['title'] ?? ''), 100);
                $body = cap_text((string) ($_POST['body'] ?? ''), 1500);
                $reply = cap_text((string) ($_POST['owner_reply'] ?? ''), 1000);
                $rating = (int) ($_POST['rating'] ?? 0);

                if ($name === '' || $body === '' || $rating < 1 || $rating > 5) {
                    $_SESSION['flash'] = 'Name, rating and review text are required.';
                } else {
                    /* Changing the customer's words or rating sets the "edited" flag. A reply does not. */
                    $changed = $name !== (string) $old['display_name'] || $rating !== (int) $old['rating']
                            || $title !== (string) $old['title'] || $body !== (string) $old['body'];
                    $pdo->prepare('UPDATE reviews SET display_name = ?, rating = ?, title = ?, body = ?, owner_reply = ?, edited_by_admin = ?, updated_at = ? WHERE id = ?')
                        ->execute([$name, $rating, $title, $body, $reply, $changed ? 1 : (int) $old['edited_by_admin'], $changed ? $now : $old['updated_at'], $id]);
                }
            }
            back('?tab=reviews&open=r' . $id . '#r' . $id);
        }
        back($stay);
    }
}

$loggedIn = !empty($_SESSION['admin']);

/* ---------- Data for the dashboard ---------- */
if ($loggedIn) {
    $tab = ($_GET['tab'] ?? '') === 'reviews' ? 'reviews' : 'quotes';
    $open = (string) ($_GET['open'] ?? '');
    $flash = (string) ($_SESSION['flash'] ?? '');
    unset($_SESSION['flash']);

    $counts = array_fill_keys(STATUSES, 0);
    foreach ($pdo->query('SELECT status, COUNT(*) c FROM quotes GROUP BY status') as $r) $counts[$r['status']] = (int) $r['c'];
    $total = array_sum($counts);
    $reviewTotal = (int) $pdo->query('SELECT COUNT(*) FROM reviews')->fetchColumn();

    if ($tab === 'quotes') {
        $filter = in_array($_GET['status'] ?? '', STATUSES, true) ? $_GET['status'] : '';
        $q = trim((string) ($_GET['q'] ?? ''));

        $sql = 'SELECT * FROM quotes WHERE 1=1';
        $args = [];
        if ($filter !== '') { $sql .= ' AND status = ?'; $args[] = $filter; }
        if ($q !== '') {
            $sql .= ' AND (name LIKE ? OR email LIKE ? OR phone LIKE ? OR details LIKE ?)';
            array_push($args, ...array_fill(0, 4, '%' . $q . '%'));
        }
        $sql .= ' ORDER BY id DESC LIMIT 200';
        $st = $pdo->prepare($sql);
        $st->execute($args);
        $rows = $st->fetchAll();
    } else {
        $links = $pdo->query('SELECT l.*, r.id AS review_id FROM review_links l LEFT JOIN reviews r ON r.link_id = l.id ORDER BY l.id DESC LIMIT 200')->fetchAll();
        $reviews = $pdo->query('SELECT r.*, l.client_name, l.handle FROM reviews r JOIN review_links l ON l.id = r.link_id ORDER BY r.id DESC LIMIT 200')->fetchAll();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Admin | EMBERENCE DIGITAL</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Manrope:wght@500;700;800&display=swap" rel="stylesheet">
  <style>
    :root { --dark:#171A1C; --lime:#B8F34A; --off:#F5F5F2; --text:#30363B; --muted:#777; --white:#fff; --line:rgba(23,26,28,.12); --error:#B3261E; }
    *, *::before, *::after { box-sizing: border-box; }
    body { margin:0; font:400 1rem/1.6 'Inter',system-ui,sans-serif; color:var(--text); background:var(--off); }
    h1,h2,h3 { font-family:'Manrope',system-ui,sans-serif; color:var(--dark); margin:0; letter-spacing:-.02em; }
    a { color:inherit; }
    :focus-visible { outline:3px solid var(--lime); outline-offset:2px; }
    .sr { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; }
    .wrap { width:min(1000px,100% - 2rem); margin-inline:auto; }
    header { background:var(--dark); color:var(--off); }
    header .wrap { display:flex; align-items:center; justify-content:space-between; height:68px; }
    .brand b { font:800 1.1rem 'Manrope',sans-serif; letter-spacing:.08em; }
    .brand span { display:block; font:600 .6rem 'Manrope',sans-serif; letter-spacing:.5em; color:var(--lime); }
    .btn { font:600 .9rem 'Manrope',sans-serif; padding:.65rem 1.1rem; border-radius:8px; border:1.5px solid transparent; cursor:pointer; background:var(--lime); color:var(--dark); text-decoration:none; display:inline-block; }
    .btn:hover { background:var(--white); }
    .btn-ghost { background:transparent; color:var(--off); border-color:rgba(245,245,242,.4); }
    .btn-ghost:hover { background:rgba(245,245,242,.1); }
    .btn-dark { background:var(--dark); color:var(--off); } .btn-dark:hover { background:var(--text); }
    .btn-danger { background:transparent; color:var(--error); border-color:var(--error); } .btn-danger:hover { background:rgba(179,38,30,.08); }
    main { padding:2rem 0 4rem; }
    .banner { background:rgba(179,38,30,.08); color:var(--error); padding:.8rem 1rem; border-radius:8px; margin-bottom:1rem; font-size:.92rem; }
    /* login */
    .login { max-width:380px; margin:4rem auto; background:var(--white); border:1px solid var(--line); border-radius:14px; padding:2rem; }
    .login h1 { font-size:1.6rem; margin-bottom:1.2rem; }
    label { display:block; font:600 .9rem 'Manrope',sans-serif; color:var(--dark); margin:0 0 .35rem; }
    input[type=text], input[type=password], input[type=search], select, textarea { width:100%; padding:.7rem .9rem; font:inherit; background:var(--off); border:1.5px solid rgba(23,26,28,.18); border-radius:8px; margin-bottom:1rem; }
    textarea { min-height:110px; resize:vertical; }
    input:focus, select:focus, textarea:focus { outline:none; border-color:var(--dark); box-shadow:0 0 0 3px var(--lime); }
    /* tabs */
    .tabs { display:flex; gap:.4rem; border-bottom:1px solid var(--line); margin-bottom:1.5rem; }
    .tab { padding:.7rem 1.1rem; font:700 .95rem 'Manrope',sans-serif; text-decoration:none; color:var(--muted); border-bottom:3px solid transparent; margin-bottom:-1px; }
    .tab.on { color:var(--dark); border-color:var(--lime); }
    .sub { font-size:1.25rem; margin:2rem 0 .8rem; }
    /* dashboard */
    .stats { display:flex; flex-wrap:wrap; gap:.6rem; margin:1rem 0 1.2rem; }
    .chip { padding:.45rem .9rem; border-radius:999px; background:var(--white); border:1px solid var(--line); font:600 .88rem 'Manrope',sans-serif; text-decoration:none; color:var(--dark); }
    .chip.on { background:var(--dark); color:var(--off); border-color:var(--dark); }
    .search { display:flex; gap:.6rem; } .search input { margin:0; }
    .req { background:var(--white); border:1px solid var(--line); border-radius:12px; margin-bottom:.8rem; }
    .req summary { list-style:none; cursor:pointer; display:grid; grid-template-columns:1fr auto; gap:.2rem 1rem; padding:1rem 1.2rem; }
    .req summary::-webkit-details-marker { display:none; }
    .req .who { font:700 1.02rem 'Manrope',sans-serif; color:var(--dark); }
    .req .meta { grid-column:1; font-size:.88rem; color:var(--muted); }
    .badge { grid-row:1 / span 2; grid-column:2; align-self:center; padding:.25rem .7rem; border-radius:999px; font:700 .78rem 'Manrope',sans-serif; background:var(--off); border:1px solid var(--line); }
    .badge.New, .badge.ok { background:var(--lime); border-color:var(--lime); color:var(--dark); }
    .badge.off { color:var(--error); border-color:rgba(179,38,30,.35); }
    .body { padding:0 1.2rem 1.2rem; border-top:1px solid var(--line); }
    .body dl { display:grid; grid-template-columns:110px 1fr; gap:.5rem 1rem; margin:1rem 0; }
    .body dt { font:600 .85rem 'Manrope',sans-serif; color:var(--muted); } .body dd { margin:0; word-break:break-word; }
    .msg { white-space:pre-wrap; background:var(--off); border-radius:8px; padding:.8rem 1rem; }
    .actions { display:flex; flex-wrap:wrap; gap:.6rem; align-items:center; margin-top:1rem; }
    .actions form { display:flex; gap:.5rem; align-items:center; margin:0; } .actions select { width:auto; margin:0; padding:.55rem .7rem; }
    .empty { text-align:center; padding:3rem 1rem; color:var(--muted); }
    /* reviews tab */
    .gen { display:grid; grid-template-columns:1fr 1fr auto; gap:.8rem; align-items:end; background:var(--white); border:1px solid var(--line); border-radius:12px; padding:1.2rem; }
    .gen input { margin:0; }
    .copy { display:flex; gap:.6rem; margin:1rem 0 .6rem; } .copy input { margin:0; }
    .note { font-size:.88rem; color:var(--muted); margin:0; }
    .stars { letter-spacing:.1em; color:var(--dark); }
    .edit { margin-top:1rem; }
    @media (max-width:560px){ .body dl { grid-template-columns:1fr; gap:.1rem; } .body dt { margin-top:.6rem; } .gen { grid-template-columns:1fr; } .copy { flex-direction:column; } }
  </style>
</head>
<body>

<?php if (!$loggedIn): ?>
  <main>
    <form class="login" method="post" autocomplete="off">
      <h1>Admin login</h1>
      <?php if ($error): ?><p class="banner" role="alert"><?= e($error) ?></p><?php endif; ?>
      <input type="hidden" name="action" value="login">
      <label for="u">Username</label>
      <input type="text" id="u" name="username" autocomplete="username" required autofocus>
      <label for="p">Password</label>
      <input type="password" id="p" name="password" autocomplete="current-password" required>
      <button class="btn btn-dark" type="submit">Log in</button>
    </form>
  </main>

<?php else: ?>
  <header>
    <div class="wrap">
      <div class="brand"><b>EMBERENCE</b><span>DIGITAL · ADMIN</span></div>
      <form method="post" style="margin:0">
        <input type="hidden" name="action" value="logout"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
        <button class="btn btn-ghost" type="submit">Log out</button>
      </form>
    </div>
  </header>

  <main class="wrap">
    <nav class="tabs" aria-label="Sections">
      <a class="tab <?= $tab === 'quotes' ? 'on' : '' ?>" href="index.php" <?= $tab === 'quotes' ? 'aria-current="page"' : '' ?>>Quote requests (<?= $total ?>)</a>
      <a class="tab <?= $tab === 'reviews' ? 'on' : '' ?>" href="?tab=reviews" <?= $tab === 'reviews' ? 'aria-current="page"' : '' ?>>Reviews (<?= $reviewTotal ?>)</a>
    </nav>

<?php if ($tab === 'quotes'): ?>
    <h1>Quote requests</h1>

    <div class="stats">
      <a class="chip <?= $filter === '' ? 'on' : '' ?>" href="index.php">All (<?= $total ?>)</a>
      <?php foreach (STATUSES as $s): ?>
        <a class="chip <?= $filter === $s ? 'on' : '' ?>" href="?status=<?= urlencode($s) ?>"><?= e($s) ?> (<?= $counts[$s] ?>)</a>
      <?php endforeach; ?>
    </div>

    <form class="search" method="get" role="search" style="margin-bottom:1.2rem">
      <?php if ($filter): ?><input type="hidden" name="status" value="<?= e($filter) ?>"><?php endif; ?>
      <input type="search" name="q" value="<?= e($q) ?>" placeholder="Search name, email, phone or message" aria-label="Search requests">
      <button class="btn btn-dark" type="submit">Search</button>
    </form>

    <?php if (!$rows): ?>
      <p class="empty">No requests found.</p>
    <?php endif; ?>

    <?php foreach ($rows as $r): ?>
      <details class="req">
        <summary>
          <span class="who"><?= e($r['name']) ?></span>
          <span class="badge <?= $r['status'] === 'New' ? 'New' : '' ?>"><?= e($r['status']) ?></span>
          <span class="meta"><?= e($r['email']) ?> · <?= e(when($r['created_at'])) ?></span>
        </summary>
        <div class="body">
          <dl>
            <dt>Email</dt><dd><a href="mailto:<?= e($r['email']) ?>"><?= e($r['email']) ?></a></dd>
            <dt>Phone</dt><dd><?= $r['phone'] !== '' ? '<a href="tel:' . e(preg_replace('/[^0-9+]/', '', $r['phone'])) . '">' . e($r['phone']) . '</a>' : 'Not provided' ?></dd>
            <dt>Address</dt><dd><?= $r['address'] !== '' ? e($r['address']) : 'Not provided' ?></dd>
            <dt>Looking for</dt><dd><div class="msg"><?= e($r['details']) ?></div></dd>
          </dl>
          <div class="actions">
            <form method="post">
              <input type="hidden" name="action" value="status"><input type="hidden" name="id" value="<?= (int) $r['id'] ?>"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
              <label for="s<?= (int) $r['id'] ?>" class="sr">Status</label>
              <select id="s<?= (int) $r['id'] ?>" name="status">
                <?php foreach (STATUSES as $s): ?><option <?= $s === $r['status'] ? 'selected' : '' ?>><?= e($s) ?></option><?php endforeach; ?>
              </select>
              <button class="btn btn-dark" type="submit">Update</button>
            </form>
            <a class="btn" href="mailto:<?= e($r['email']) ?>?subject=<?= rawurlencode('Your quote request - Emberence Digital') ?>">Reply by email</a>
            <form method="post">
              <input type="hidden" name="action" value="link_create"><input type="hidden" name="quote_id" value="<?= (int) $r['id'] ?>"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
              <button class="btn btn-dark" type="submit">Get review link</button>
            </form>
            <form method="post" onsubmit="return confirm('Delete this request permanently?');">
              <input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= (int) $r['id'] ?>"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
              <button class="btn btn-danger" type="submit">Delete</button>
            </form>
          </div>
        </div>
      </details>
    <?php endforeach; ?>

<?php else: ?>
    <h1>Reviews</h1>
    <?php if ($flash): ?><p class="banner" role="alert" style="margin-top:1rem"><?= e($flash) ?></p><?php endif; ?>

    <h2 class="sub">Review links</h2>
    <form class="gen" method="post">
      <input type="hidden" name="action" value="link_create"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <div>
        <label for="cn">Client name</label>
        <input type="text" id="cn" name="client_name" maxlength="100" required>
      </div>
      <div>
        <label for="ch">Instagram or other handle (optional)</label>
        <input type="text" id="ch" name="handle" maxlength="60">
      </div>
      <button class="btn btn-dark" type="submit">Generate link</button>
    </form>
    <p class="note" style="margin:.6rem 0 1.2rem">For a client who sent a quote request, use "Get review link" on their request instead. Links work for <?= (int) REVIEW_LINK_DAYS ?> days.</p>

    <?php if (!$links): ?><p class="empty">No review links yet.</p><?php endif; ?>

    <?php foreach ($links as $l): [$label, $cls] = link_state($l); $lid = (int) $l['id']; ?>
      <details class="req" id="l<?= $lid ?>" <?= $open === 'l' . $lid ? 'open' : '' ?>>
        <summary>
          <span class="who"><?= e($l['client_name']) ?></span>
          <span class="badge <?= e($cls) ?>"><?= e($label) ?></span>
          <span class="meta"><?= $l['handle'] !== '' && $l['handle'] !== null ? e($l['handle']) . ' · ' : '' ?>Created <?= e(when($l['created_at'])) ?> · Expires <?= e(when($l['expires_at'])) ?></span>
        </summary>
        <div class="body">
          <div class="copy">
            <label for="url<?= $lid ?>" class="sr">Review link</label>
            <input type="text" id="url<?= $lid ?>" readonly value="<?= e(link_url($l['token'])) ?>">
            <button class="btn btn-dark" type="button" data-copy="url<?= $lid ?>">Copy link</button>
          </div>
          <p class="note"><?= e(STATE_NOTES[$label]) ?></p>
          <div class="actions">
            <?php if ($l['status'] !== 'revoked'): ?>
            <form method="post" onsubmit="return confirm('Switch this link off? The client will not be able to use it.');">
              <input type="hidden" name="action" value="link_revoke"><input type="hidden" name="id" value="<?= $lid ?>"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
              <button class="btn btn-danger" type="submit">Revoke</button>
            </form>
            <?php endif; ?>
            <form method="post" onsubmit="return confirm('Make a new link? The old link will stop working.');">
              <input type="hidden" name="action" value="link_regen"><input type="hidden" name="id" value="<?= $lid ?>"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
              <button class="btn btn-dark" type="submit">Regenerate</button>
            </form>
          </div>
        </div>
      </details>
    <?php endforeach; ?>

    <h2 class="sub">Client reviews</h2>
    <?php if (!$reviews): ?><p class="empty">No reviews yet. They appear here as soon as a client submits one.</p><?php endif; ?>

    <?php foreach ($reviews as $r): $rid = (int) $r['id']; $pub = $r['status'] === 'published'; ?>
      <details class="req" id="r<?= $rid ?>" <?= $open === 'r' . $rid ? 'open' : '' ?>>
        <summary>
          <span class="who"><span class="stars" aria-label="<?= (int) $r['rating'] ?> out of 5 stars"><?= e(stars((int) $r['rating'])) ?></span> <?= e($r['display_name']) ?></span>
          <span class="badge <?= $pub ? 'ok' : 'off' ?>"><?= $pub ? 'Published' : 'Hidden' ?></span>
          <span class="meta"><?= e(when($r['created_at'])) ?><?= $r['edited_by_admin'] ? ' · Edited by admin' : '' ?><?= $r['owner_reply'] !== '' && $r['owner_reply'] !== null ? ' · Replied' : '' ?></span>
        </summary>
        <div class="body">
          <dl>
            <dt>Client</dt><dd><?= e($r['client_name']) ?><?= $r['handle'] ? ' (' . e($r['handle']) . ')' : '' ?></dd>
            <dt>Submitted</dt><dd><?= e(when($r['created_at'])) ?></dd>
            <?php if ($r['updated_at'] !== $r['created_at']): ?><dt>Last changed</dt><dd><?= e(when($r['updated_at'])) ?></dd><?php endif; ?>
          </dl>
          <?php if ($r['edited_by_admin']): ?><p class="note" style="margin-bottom:1rem">This review was edited by admin, so the wording may differ from what the client wrote. This is not shown publicly.</p><?php endif; ?>

          <form method="post" class="edit">
            <input type="hidden" name="action" value="review_save"><input type="hidden" name="id" value="<?= $rid ?>"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
            <label for="rn<?= $rid ?>">Name shown</label>
            <input type="text" id="rn<?= $rid ?>" name="display_name" maxlength="60" value="<?= e($r['display_name']) ?>" required>
            <label for="rr<?= $rid ?>">Rating</label>
            <select id="rr<?= $rid ?>" name="rating">
              <?php for ($i = 5; $i >= 1; $i--): ?><option value="<?= $i ?>" <?= $i === (int) $r['rating'] ? 'selected' : '' ?>><?= $i ?> <?= $i === 1 ? 'star' : 'stars' ?></option><?php endfor; ?>
            </select>
            <label for="rt<?= $rid ?>">Headline</label>
            <input type="text" id="rt<?= $rid ?>" name="title" maxlength="100" value="<?= e($r['title']) ?>">
            <label for="rb<?= $rid ?>">Review</label>
            <textarea id="rb<?= $rid ?>" name="body" maxlength="1500" required><?= e($r['body']) ?></textarea>
            <label for="ry<?= $rid ?>">Reply from Emberence (shown publicly under the review)</label>
            <textarea id="ry<?= $rid ?>" name="owner_reply" maxlength="1000"><?= e($r['owner_reply']) ?></textarea>
            <button class="btn btn-dark" type="submit">Save changes</button>
          </form>

          <div class="actions">
            <form method="post">
              <input type="hidden" name="action" value="review_visibility"><input type="hidden" name="id" value="<?= $rid ?>"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
              <input type="hidden" name="to" value="<?= $pub ? 'hidden' : 'published' ?>">
              <button class="btn btn-dark" type="submit"><?= $pub ? 'Hide from site' : 'Show on site' ?></button>
            </form>
            <form method="post" onsubmit="return confirm('Delete this review permanently? The client could submit a new one with the same link unless you revoke it.');">
              <input type="hidden" name="action" value="review_delete"><input type="hidden" name="id" value="<?= $rid ?>"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
              <button class="btn btn-danger" type="submit">Delete</button>
            </form>
          </div>
        </div>
      </details>
    <?php endforeach; ?>

    <script>
      /* Copy a review link to the clipboard */
      document.addEventListener('click', function (ev) {
        var b = ev.target.closest('[data-copy]');
        if (!b) return;
        var input = document.getElementById(b.getAttribute('data-copy'));
        input.focus(); input.select();
        var done = function () { var t = b.textContent; b.textContent = 'Copied'; setTimeout(function () { b.textContent = t; }, 1500); };
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(input.value).then(done, function () { document.execCommand('copy'); done(); });
        } else { document.execCommand('copy'); done(); }
      });
    </script>
<?php endif; ?>
  </main>
<?php endif; ?>

</body>
</html>
