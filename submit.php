<?php
/* Receives the quote form (JSON) and saves it to the database */
require __DIR__ . '/../includes/bootstrap.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function out(int $code, string $result) {
    http_response_code($code);
    echo json_encode(['result' => $result]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(405, 'error');

$data = json_decode((string) file_get_contents('php://input', false, null, 0, 20000), true);
if (!is_array($data)) out(400, 'error');

/* Trim and cap length (UTF-8 safe, works even if the mbstring extension is missing) */
$get = function (string $k, int $max) use ($data): string {
    $v = trim((string) ($data[$k] ?? ''));
    preg_match('/^.{0,' . $max . '}/su', $v, $m);
    return $m[0] ?? '';
};
$name = $get('name', 100);
$email = $get('email', 150);
$phone = $get('phone', 30);
$address = $get('address', 300);
$details = $get('details', 3000);

/* Server-side validation (the browser checks too, but never trust only the browser) */
if (strlen($name) < 2 || !filter_var($email, FILTER_VALIDATE_EMAIL) || $details === ''
    || ($phone !== '' && !preg_match('/^[0-9+()\-\s]{7,20}$/', $phone))) {
    out(422, 'error');
}

try {
    $pdo = db();
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';

    /* Basic spam protection: max 5 requests per IP per hour */
    $st = $pdo->prepare('SELECT COUNT(*) FROM quotes WHERE ip = ? AND created_at > ?');
    $st->execute([$ip, gmdate('Y-m-d H:i:s', time() - 3600)]);
    if ((int) $st->fetchColumn() >= 5) out(429, 'error');

    $pdo->prepare('INSERT INTO quotes (name, email, phone, address, details, ip, created_at) VALUES (?,?,?,?,?,?,?)')
        ->execute([$name, $email, $phone, $address, $details, $ip, gmdate('Y-m-d H:i:s')]);
    out(200, 'success');
} catch (Throwable $e) {
    out(500, 'error');
}
