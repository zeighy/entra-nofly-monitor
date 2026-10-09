#!/usr/bin/env php
<?php
// Rebuilds all derived risk data (user baselines, risk events and user risk scores)
// from the sign-ins and MFA device changes already stored in the database.
//
// Run it once after migrate_risk_scoring.php, and again after reprocess_logs.php or
// after changing risk weights/thresholds in secrets.php. It does not touch login_logs,
// does not call Microsoft Graph and never sends email.

if (php_sapi_name() !== 'cli') {
    die('This script can only be run from the command line.');
}

$autoloader = __DIR__ . '/vendor/autoload.php';
if (!file_exists($autoloader)) {
    die("FATAL ERROR: Composer autoloader not found. Please run 'composer install'.\n");
}
require_once $autoloader;

$secretsFile = __DIR__ . '/secrets.php';
if (!file_exists($secretsFile)) {
    die("FATAL ERROR: secrets.php file not found.\n");
}
$secrets = require $secretsFile;
foreach ($secrets as $key => $value) {
    $_ENV[$key] = $value;
}

use App\Database;
use App\RiskScorer;

$db = Database::getInstance();
$scorer = new RiskScorer($db);

echo "Clearing existing baselines, risk events and risk scores...\n";
$scorer->resetAll();

// Walk every sign-in oldest to newest so each one is judged only against what came before it.
$total = (int)$db->query("SELECT COUNT(*) FROM login_logs")->fetchColumn();
echo "Scoring $total sign-ins...\n";

$stmt = $db->prepare("SELECT * FROM login_logs WHERE (login_time, id) > (?, ?) ORDER BY login_time ASC, id ASC LIMIT 1000");
$lastTime = '0000-00-00 00:00:00';
$lastId = 0;
$done = 0;
$signalCount = 0;
while (true) {
    $stmt->execute([$lastTime, $lastId]);
    $rows = $stmt->fetchAll();
    if (!$rows) break;
    foreach ($rows as $row) {
        $signalCount += count($scorer->scoreLogin($row));
        $lastTime = $row['login_time'];
        $lastId = (int)$row['id'];
        $done++;
    }
    echo "  $done / $total\r";
}
echo "\n";

// MFA device changes. If a user's history opens with a burst of "Added" rows, that is the
// initial snapshot of devices they already had (see populate_devices.php), not new devices.
$changes = $db->query("SELECT * FROM auth_device_changes ORDER BY user_id, change_time ASC, id ASC")->fetchAll();
$byUser = [];
foreach ($changes as $change) {
    $byUser[$change['user_id']][] = $change;
}
$scoredChanges = 0;
$skippedChanges = 0;
foreach ($byUser as $userChanges) {
    $firstTime = strtotime($userChanges[0]['change_time']);
    $openingAdds = array_filter($userChanges, fn($c) => strtolower($c['change_type']) === 'added' && strtotime($c['change_time']) <= $firstTime + 300);
    $isInitialSnapshot = count($openingAdds) >= 2;
    $openingIds = array_column($openingAdds, 'id');
    foreach ($userChanges as $change) {
        if ($isInitialSnapshot && in_array($change['id'], $openingIds)) {
            $skippedChanges++;
            continue;
        }
        $scorer->scoreDeviceChange((int)$change['id']);
        $scoredChanges++;
    }
}
echo "MFA device changes: $scoredChanges scored, $skippedChanges skipped as initial device snapshots.\n";

$tiers = $scorer->refreshAllScores();
$events = (int)$db->query("SELECT COUNT(*) FROM risk_events")->fetchColumn();
echo "\nDone. $events risk events recorded across the full history.\n";
echo "Users currently in the current scoring window by tier: ";
echo implode(', ', array_map(fn($t, $n) => "$n $t", array_keys($tiers), $tiers)) . "\n";
