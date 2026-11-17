<?php
/* Public, read-only: published reviews + average rating for the website.
   Optional ?limit=6 (default 12, max 50) and ?offset=0 for paging. Never returns emails, handles or link tokens. */
require __DIR__ . '/../includes/bootstrap.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['result' => 'error']);
    exit;
}

$limit = max(1, min(50, (int) ($_GET['limit'] ?? 12)));
$offset = max(0, (int) ($_GET['offset'] ?? 0));

try {
    $pdo = db();
    $stats = $pdo->query("SELECT COUNT(*) AS c, AVG(rating) AS a FROM reviews WHERE status = 'published'")->fetch();

    $st = $pdo->prepare("SELECT display_name, rating, title, body, owner_reply FROM reviews WHERE status = 'published' ORDER BY id DESC LIMIT " . $limit . " OFFSET " . $offset);
    $st->execute();

    $items = [];
    foreach ($st->fetchAll() as $r) {
        $items[] = [
            'name'   => (string) $r['display_name'],
            'rating' => (int) $r['rating'],
            'title'  => (string) $r['title'],
            'body'   => (string) $r['body'],
            'reply'  => (string) $r['owner_reply'],
        ];
    }

    /* How many published reviews per star rating (for the bars on the homepage) */
    $dist = [1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0];
    foreach ($pdo->query("SELECT rating, COUNT(*) AS c FROM reviews WHERE status = 'published' GROUP BY rating") as $row) {
        $dist[(int) $row['rating']] = (int) $row['c'];
    }

    echo json_encode([
        'result'  => 'ok',
        'count'   => (int) $stats['c'],
        'distribution' => $dist,
        'average' => $stats['c'] > 0 ? round((float) $stats['a'], 1) : 0,
        'reviews' => $items,
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['result' => 'error']);
}
