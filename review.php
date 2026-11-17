<?php
/* Review page API
   GET  ?t=TOKEN                          -> what state the link is in (new / existing / expired / revoked / invalid)
   POST {t, action: submit|update|delete} -> saves the client's own review */
require __DIR__ . '/../includes/bootstrap.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

function out(int $code, array $payload) {
    http_response_code($code);
    echo json_encode($payload);
    exit;
}

function review_view(array $r): array {
    return [
        'name'   => (string) $r['display_name'],
        'rating' => (int) $r['rating'],
        'title'  => (string) $r['title'],
        'body'   => (string) $r['body'],
        'reply'  => (string) $r['owner_reply'],
    ];
}

$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
if (!$isPost && $_SERVER['REQUEST_METHOD'] !== 'GET') out(405, ['result' => 'error']);

$data = [];
if ($isPost) {
    $data = json_decode((string) file_get_contents('php://input', false, null, 0, 20000), true);
    if (!is_array($data)) out(400, ['result' => 'error']);
}
$token = (string) ($isPost ? ($data['t'] ?? '') : ($_GET['t'] ?? ''));

try {
    $pdo = db();
    $ip  = $_SERVER['REMOTE_ADDR'] ?? '';
    $now = gmdate('Y-m-d H:i:s');

    /* Slow down anyone guessing links: max 20 wrong tokens per IP per 15 minutes */
    $pdo->prepare('DELETE FROM token_attempts WHERE created_at < ?')->execute([gmdate('Y-m-d H:i:s', time() - 900)]);
    $st = $pdo->prepare('SELECT COUNT(*) FROM token_attempts WHERE ip = ?');
    $st->execute([$ip]);
    if ((int) $st->fetchColumn() >= 20) out(429, ['result' => 'error', 'state' => 'throttled']);

    $link = false;
    if (preg_match('/^[a-f0-9]{48}$/', $token)) {
        $st = $pdo->prepare('SELECT * FROM review_links WHERE token = ?');
        $st->execute([$token]);
        $link = $st->fetch();
    }
    if (!$link) {
        $pdo->prepare('INSERT INTO token_attempts (ip, created_at) VALUES (?, ?)')->execute([$ip, $now]);
        usleep(400000);
        out(404, ['result' => 'error', 'state' => 'invalid']);
    }

    if ($link['status'] === 'revoked') out(200, ['result' => 'error', 'state' => 'revoked']);

    $st = $pdo->prepare('SELECT * FROM reviews WHERE link_id = ?');
    $st->execute([$link['id']]);
    $review = $st->fetch();

    /* Expiry only blocks writing a NEW review. Once a review exists, the client can always edit or delete it. */
    $expired = !$review && $link['expires_at'] < $now;

    /* ----- GET: tell the page what to show ----- */
    if (!$isPost) {
        if ($review)  out(200, ['result' => 'ok', 'state' => 'existing', 'review' => review_view($review)]);
        if ($expired) out(200, ['result' => 'ok', 'state' => 'expired']);
        out(200, ['result' => 'ok', 'state' => 'new', 'name' => (string) $link['client_name']]);
    }

    /* ----- POST ----- */
    if (!empty($data['website'])) out(200, ['result' => 'success']);   // honeypot: bots fill this hidden field

    $action = (string) ($data['action'] ?? '');

    if ($action === 'delete') {
        if ($review) $pdo->prepare('DELETE FROM reviews WHERE id = ?')->execute([$review['id']]);
        out(200, ['result' => 'success']);
    }
    if ($action !== 'submit' && $action !== 'update') out(400, ['result' => 'error']);

    $name   = cap_text((string) ($data['display_name'] ?? ''), 60);
    $title  = cap_text((string) ($data['title'] ?? ''), 100);
    $body   = cap_text((string) ($data['body'] ?? ''), 1500);
    $rating = (int) ($data['rating'] ?? 0);

    /* Server-side validation (the browser checks too, but never trust only the browser) */
    if (char_len($name) < 2 || char_len($body) < 10 || $rating < 1 || $rating > 5) {
        out(422, ['result' => 'error', 'reason' => 'validation']);
    }

    if ($action === 'submit') {
        if ($review)  out(409, ['result' => 'error', 'reason' => 'exists']);
        if ($expired) out(200, ['result' => 'error', 'state' => 'expired']);
        $pdo->prepare('INSERT INTO reviews (link_id, display_name, rating, title, body, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)')
            ->execute([$link['id'], $name, $rating, $title, $body, 'published', $now, $now]);
    } else {
        if (!$review) out(404, ['result' => 'error', 'reason' => 'missing']);
        /* A client edit replaces the wording, so the "edited by admin" flag is cleared. Hidden/published status is kept. */
        $pdo->prepare('UPDATE reviews SET display_name = ?, rating = ?, title = ?, body = ?, edited_by_admin = 0, updated_at = ? WHERE id = ?')
            ->execute([$name, $rating, $title, $body, $now, $review['id']]);
    }
    out(200, ['result' => 'success']);
} catch (Throwable $e) {
    out(500, ['result' => 'error', 'reason' => 'server']);
}
