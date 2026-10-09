<?php
define('BASE_PATH', '/nofly-watch/public/index.php');

// --- Session Handling ---
$session_path = __DIR__ . '/../sessions';
if (!is_dir($session_path)) {
    if (!@mkdir($session_path, 0777, true) && !is_dir($session_path)) {
         die("FATAL ERROR: Could not create session directory at '$session_path'. Please verify permissions.");
    }
}
session_save_path($session_path);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
// --- End Session Handling ---

require_once __DIR__ . '/../vendor/autoload.php';

// Load credentials from secrets.php
$secretsFile = __DIR__ . '/../secrets.php';
if (!file_exists($secretsFile)) {
    die("FATAL ERROR: secrets.php file not found. Please create it in the project root.");
}
$secrets = require $secretsFile;
foreach ($secrets as $key => $value) {
    $_ENV[$key] = $value;
    if (!is_array($value)) {
        putenv("$key=$value");
    }
}

use App\Auth;
use App\Database;

$auth = new Auth();
$db = Database::getInstance();
$errorMessage = '';
$infoMessage = '';

require_once __DIR__ . '/partials/nav.php';

function h($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

// A timestamp stored in UTC; the script at the bottom of the page rewrites it into the viewer's timezone.
function utcTime(?string $timestamp): string {
    if (!$timestamp) return '';
    return '<span class="utc-time" data-timestamp="' . h($timestamp) . ' UTC">' . h($timestamp) . ' UTC</span>';
}

// Same as utcTime() but rendered without seconds/year, for narrow columns.
function utcShort(?string $timestamp): string {
    if (!$timestamp) return '';
    return '<span class="utc-short" data-timestamp="' . h($timestamp) . ' UTC">' . h($timestamp) . ' UTC</span>';
}

function tierBadge(string $tier): string {
    return '<span class="badge tier-' . h($tier) . '">' . h(ucfirst($tier)) . '</span>';
}

if (isset($_SESSION['info_message'])) {
    $infoMessage = $_SESSION['info_message'];
    unset($_SESSION['info_message']); 
}

// --- Login and Action Logic ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $turnstileResponse = $_POST['cf-turnstile-response'] ?? '';
    $turnstileSecret = $_ENV['TURNSTILE_SECRET_KEY'] ?? '';
    
    // Skip verification if keys are completely missing from environment to avoid locking users out
    // but if secret is there we should verify.
    $captchaValid = false;
    if (empty($turnstileSecret)) {
        $captchaValid = true; // Fallback if no turnstile configured
    } else {
        if (!empty($turnstileResponse)) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, 'https://challenges.cloudflare.com/turnstile/v0/siteverify');
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
                'secret' => $turnstileSecret,
                'response' => $turnstileResponse,
                'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
            ]));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response = curl_exec($ch);
            curl_close($ch);
            
            if ($response) {
                $result = json_decode($response, true);
                if (isset($result['success']) && $result['success']) {
                    $captchaValid = true;
                }
            }
        }
    }

    if (!$captchaValid) {
        $errorMessage = 'CAPTCHA validation failed. Please try again.';
    } elseif ($auth->login($_POST['username'], $_POST['password'])) {
        header('Location: ' . BASE_PATH);
        exit;
    } else {
        $errorMessage = 'Invalid username or password.';
    }
}

if (isset($_GET['logout'])) {
    $auth->logout();
    header('Location: ' . BASE_PATH);
    exit;
}

if ($auth->check()) {
    // --- Handle Whitelist, Export, and Reprocess Actions via POST ---
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['add_whitelist'])) {
            if (!empty($_POST['ip_address'])) {
                $stmt = $db->prepare("INSERT INTO ip_whitelist (ip_address, note) VALUES (?, ?)");
                $stmt->execute([$_POST['ip_address'], $_POST['note']]);
                $_SESSION['info_message'] = "IP address added to whitelist.";
                header('Location: ' . BASE_PATH);
                exit;
            }
        }
        if (isset($_POST['delete_whitelist'])) {
            if (!empty($_POST['whitelist_id'])) {
                $stmt = $db->prepare("DELETE FROM ip_whitelist WHERE id = ?");
                $stmt->execute([$_POST['whitelist_id']]);
                $_SESSION['info_message'] = "IP address removed from whitelist.";
                header('Location: ' . BASE_PATH);
                exit;
            }
        }
        if (isset($_POST['export_data'])) {
            $exportType = $_POST['export_type'] ?? 'none';
            $filename = "export_" . $exportType . "_" . date('Y-m-d') . ".csv";
            header('Content-Type: text/csv');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            
            $output = fopen('php://output', 'w');
            $escape_char = '\\';

            switch ($exportType) {
                case 'alerts_24hr':
                case 'alerts_all':
                    fputcsv($output, ['User', 'Alert Type', 'Status', 'From Location', 'From Time', 'To Location', 'To Time', 'Speed (km/h)', 'Email Sent', 'Email Sent At'], ',', '"', $escape_char);
                    $sql = "SELECT l.*, e.sent_at as email_sent_at FROM login_logs l LEFT JOIN email_alerts e ON l.id = e.alert_log_id AND l.previous_log_id = e.compared_log_id WHERE (l.is_impossible_travel = 1 OR l.is_region_change = 1)";
                    if ($exportType === 'alerts_24hr') {
                        $sql .= " AND l.login_time >= NOW() - INTERVAL 1 DAY";
                    }
                    $sql .= " ORDER BY l.login_time DESC";
                    $stmt = $db->query($sql);
                    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                        $prevStmt = $db->prepare("SELECT * FROM login_logs WHERE id = ?");
                        $prevStmt->execute([$row['previous_log_id']]);
                        $prevRow = $prevStmt->fetch(PDO::FETCH_ASSOC);
                        $alertType = $row['is_impossible_travel'] ? 'Impossible Travel' : 'Region Change';
                        $csvRow = [$row['user_principal_name'], $alertType, $row['status'], ($prevRow['city'] ?? '') . ', ' . ($prevRow['region'] ?? '') . ', ' . ($prevRow['country'] ?? ''), $prevRow['login_time'] ?? '', ($row['city'] ?? '') . ', ' . ($row['region'] ?? '') . ', ' . ($row['country'] ?? ''), $row['login_time'], round($row['travel_speed_kph']), $row['email_sent_at'] ? 'Yes' : 'No', $row['email_sent_at'] ?? 'N/A'];
                        fputcsv($output, $csvRow, ',', '"', $escape_char);
                    }
                    break;
                case 'signins_24hr':
                case 'signins_7day':
                case 'signins_30day':
                case 'signins_all':
                    fputcsv($output, ['User', 'Login Time (UTC)', 'Status', 'IP Address', 'Location', 'Region', 'Country'], ',', '"', $escape_char);
                    $sql = "SELECT user_principal_name, login_time, status, ip_address, city, region, country FROM login_logs";
                    if ($exportType === 'signins_24hr') {
                        $sql .= " WHERE login_time >= NOW() - INTERVAL 1 DAY";
                    } elseif ($exportType === 'signins_7day') {
                        $sql .= " WHERE login_time >= NOW() - INTERVAL 7 DAY";
                    } elseif ($exportType === 'signins_30day') {
                        $sql .= " WHERE login_time >= NOW() - INTERVAL 30 DAY";
                    }
                    $sql .= " ORDER BY login_time DESC";
                    $stmt = $db->query($sql);
                    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                        fputcsv($output, $row, ',', '"', $escape_char);
                    }
                    break;
            }
            fclose($output);
            exit;
        }

        if (isset($_POST['reprocess_logs'])) {
            $logFile = 'reprocess_output_' . date('Ymd-His') . '.log';
            header('Content-Type: text/plain');
            header('Content-Disposition: attachment; filename="' . $logFile . '"');
            
            $phpPath = trim(shell_exec('which php84'));
            if (empty($phpPath)) { $phpPath = trim(shell_exec('which php')); }
            if (empty($phpPath)) { $phpPath = '/usr/bin/php84'; }

            $scriptPath = __DIR__ . '/../reprocess_logs.php';
            
            passthru(escapeshellcmd($phpPath . " " . $scriptPath));
            exit;
        }

        if (isset($_POST['generate_api_token'])) {
            $newToken = bin2hex(random_bytes(24));
            $secretsContent = file_get_contents($secretsFile);

            if (preg_match('/\'API_TOKEN\'\s*=>\s*\'[^\']*\'/', $secretsContent)) {
                $secretsContent = preg_replace('/\'API_TOKEN\'\s*=>\s*\'[^\']*\'/', "'API_TOKEN' => '$newToken'", $secretsContent);
            } else {
                $secretsContent = preg_replace('/\];\s*$/', "    // --- API Configuration ---\n    'API_TOKEN' => '$newToken',\n];", $secretsContent);
            }

            if (file_put_contents($secretsFile, $secretsContent)) {
                $_SESSION['info_message'] = "New API Token generated successfully.";
            } else {
                $_SESSION['info_message'] = "Error: Could not write to secrets.php. Check permissions.";
            }
            header('Location: ' . BASE_PATH);
            exit;
        }
    }

    if (isset($_GET['trigger']) && $_GET['trigger'] === 'background') {
        $logDir = __DIR__ . '/../logs-6Tnx-HLFW';
        if (!is_dir($logDir)) {
            if (!@mkdir($logDir, 0777, true) && !is_dir($logDir)) {
                 $_SESSION['info_message'] = "Error: Could not create log directory at '$logDir'. Please check permissions.";
                 header('Location: ' . BASE_PATH);
                 exit;
            }
        }
        $logFile = $logDir . '/manual_' . date('Ymd-His') . '.log';
        $phpPath = trim(shell_exec('which php84'));
        if (empty($phpPath)) { $phpPath = trim(shell_exec('which php')); }
        if (empty($phpPath)) { $phpPath = '/usr/bin/php84'; }
        $scriptPath = __DIR__ . '/../run_background_task.php';
        shell_exec($phpPath . " " . $scriptPath . " > " . escapeshellarg($logFile) . " 2>&1 &");
        $_SESSION['info_message'] = "Background process triggered. Output is being logged to: " . basename($logFile);
        header('Location: ' . BASE_PATH);
        exit;
    }
    
    // --- Dashboard data ---
    $tierNames = ['critical', 'high', 'medium', 'low'];

    // Risk scoring. The tables only exist after migrate_risk_scoring.php has been run.
    $riskReady = true;
    $tierCounts = array_fill_keys($tierNames, 0);
    $riskUsers = [];
    $riskEvents = [];
    try {
        foreach ($db->query("SELECT tier, COUNT(*) AS c FROM user_risk_scores GROUP BY tier") as $row) {
            $tierCounts[$row['tier']] = (int)$row['c'];
        }
        $riskUsers = $db->query("SELECT * FROM user_risk_scores ORDER BY score DESC, last_event_at DESC LIMIT 15")->fetchAll();
        $riskEvents = $db->query("SELECT * FROM risk_events WHERE occurred_at >= NOW() - INTERVAL 7 DAY ORDER BY occurred_at DESC, id DESC LIMIT 200")->fetchAll();
    } catch (PDOException $e) {
        $riskReady = false;
    }

    // Headline numbers for the last 24 hours.
    $stats = $db->query("SELECT COUNT(*) AS total, COALESCE(SUM(status <> 'Success'), 0) AS failed, COUNT(DISTINCT user_id) AS users
                         FROM login_logs WHERE login_time >= NOW() - INTERVAL 1 DAY")->fetch();

    // Sign-ins per hour for the chart.
    $hourly = [];
    for ($i = 23; $i >= 0; $i--) {
        $hourly[gmdate('Y-m-d H', time() - $i * 3600)] = ['ok' => 0, 'fail' => 0];
    }
    foreach ($db->query("SELECT DATE_FORMAT(login_time, '%Y-%m-%d %H') AS h, SUM(status = 'Success') AS ok, SUM(status <> 'Success') AS fail
                         FROM login_logs WHERE login_time >= NOW() - INTERVAL 24 HOUR GROUP BY h") as $row) {
        if (isset($hourly[$row['h']])) {
            $hourly[$row['h']] = ['ok' => (int)$row['ok'], 'fail' => (int)$row['fail']];
        }
    }
    $hourlyMax = max(1, max(array_map(fn($b) => $b['ok'] + $b['fail'], $hourly)));

    $topCountries = $db->query("SELECT country, COUNT(*) AS c FROM login_logs
                                WHERE login_time >= NOW() - INTERVAL 1 DAY AND status = 'Success' AND country IS NOT NULL AND country <> ''
                                GROUP BY country ORDER BY c DESC LIMIT 6")->fetchAll();
    $topCountryMax = max(1, (int)($topCountries[0]['c'] ?? 1));

    // Detail tables. Previous-login and email details come from joins rather than per-row lookups.
    $travelRows = $db->query("SELECT l.*, p.city AS p_city, p.country AS p_country, p.ip_address AS p_ip, p.login_time AS p_time,
                                     (SELECT MAX(e.sent_at) FROM email_alerts e WHERE e.alert_log_id = l.id AND e.compared_log_id = l.previous_log_id AND e.alert_type = 'impossible_travel') AS email_sent_at
                              FROM login_logs l LEFT JOIN login_logs p ON p.id = l.previous_log_id
                              WHERE l.is_impossible_travel = 1 ORDER BY l.login_time DESC LIMIT 100")->fetchAll();
    $regionRows = $db->query("SELECT l.*, p.region AS p_region, p.country AS p_country, p.ip_address AS p_ip, p.login_time AS p_time,
                                     (SELECT MAX(e.sent_at) FROM email_alerts e WHERE e.alert_log_id = l.id AND e.compared_log_id = l.previous_log_id AND e.alert_type = 'region_change') AS email_sent_at
                              FROM login_logs l LEFT JOIN login_logs p ON p.id = l.previous_log_id
                              WHERE l.is_region_change = 1 ORDER BY l.login_time DESC LIMIT 100")->fetchAll();
    $deviceRows = $db->query("SELECT * FROM auth_device_changes WHERE change_time >= NOW() - INTERVAL 1 DAY ORDER BY change_time DESC")->fetchAll();
    $signinLimit = 1000;
    $signinRows = $db->query("SELECT * FROM login_logs WHERE login_time >= NOW() - INTERVAL 1 DAY ORDER BY login_time DESC LIMIT " . $signinLimit)->fetchAll();
    $whitelistRows = $db->query("SELECT * FROM ip_whitelist ORDER BY created_at DESC")->fetchAll();

    $travelCount24 = (int)$db->query("SELECT COUNT(*) FROM login_logs WHERE is_impossible_travel = 1 AND login_time >= NOW() - INTERVAL 1 DAY")->fetchColumn();
    $regionCount24 = (int)$db->query("SELECT COUNT(*) FROM login_logs WHERE is_region_change = 1 AND login_time >= NOW() - INTERVAL 1 DAY")->fetchColumn();

    $tierDefaults = ['critical' => 80, 'high' => 55, 'medium' => 30, 'low' => 15];
    $tierThresholds = [];
    foreach ($tierDefaults as $tier => $default) {
        $configured = $_ENV['RISK_TIER_' . strtoupper($tier)] ?? '';
        $tierThresholds[$tier] = $configured !== '' ? (int)$configured : $default;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra Monitor</title>
    <link rel="stylesheet" href="/nofly-watch/public/style.css">
    <?php if (!$auth->check()): ?>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <?php endif; ?>
</head>
<body>
<?php if ($auth->check()): ?>
    <?php render_nav('dashboard', $auth->getUsername()); ?>
    <div class="container">
        <main>
            <?php if ($infoMessage): ?>
                <div class="info-message"><?= icon('activity', 18) ?><?= h($infoMessage) ?></div>
            <?php endif; ?>
            <?php if (!$riskReady): ?>
                <div class="notice"><strong>Risk scoring is not set up yet.</strong> Run <code>php migrate_risk_scoring.php</code> and then <code>php rebuild_risk.php</code> from the project root.</div>
            <?php endif; ?>

            <div class="page-head">
                <div>
                    <h1>Security Dashboard</h1>
                    <p>Sign-in activity and risk across your tenant &middot; rolling 24 hours &middot; <span id="generated" data-timestamp="<?= gmdate('Y-m-d H:i:s') ?> UTC"></span></p>
                </div>
                <div class="page-actions">
                    <a href="<?= BASE_PATH ?>?trigger=background" class="btn btn-primary"><?= icon('refresh', 16) ?> Sync now</a>
                    <a href="#tools" class="btn btn-ghost" data-open-tab="tools"><?= icon('sliders', 16) ?> Tools</a>
                </div>
            </div>

            <?php $tierHints = ['critical' => 'Act now', 'high' => 'Review today', 'medium' => 'Check in', 'low' => 'Keep an eye on']; ?>
            <div class="kpi-grid" aria-label="Users by risk tier">
                <?php foreach ($tierNames as $tier): ?>
                    <div class="kpi tier-<?= $tier ?><?= $tierCounts[$tier] === 0 ? ' zero' : '' ?>">
                        <div class="kpi-label"><?= icon('zap', 14) ?> <?= ucfirst($tier) ?> risk</div>
                        <div class="kpi-value"><?= $tierCounts[$tier] ?></div>
                        <div class="kpi-sub"><?= $tierCounts[$tier] === 1 ? 'user' : 'users' ?> &middot; <?= $tierHints[$tier] ?></div>
                    </div>
                <?php endforeach; ?>
            </div>
            <div class="kpi-grid" aria-label="Activity, last 24 hours">
                <div class="kpi neutral">
                    <div class="kpi-label"><?= icon('activity', 14) ?> Sign-ins</div>
                    <div class="kpi-value"><?= number_format((int)$stats['total']) ?></div>
                    <div class="kpi-sub"><?= number_format((int)$stats['users']) ?> unique users</div>
                </div>
                <div class="kpi<?= (int)$stats['failed'] === 0 ? ' zero' : '' ?>" style="--kpi-color: var(--critical)">
                    <div class="kpi-label"><?= icon('alert', 14) ?> Failed sign-ins</div>
                    <div class="kpi-value"><?= number_format((int)$stats['failed']) ?></div>
                    <div class="kpi-sub"><?= $stats['total'] > 0 ? round($stats['failed'] / $stats['total'] * 100) : 0 ?>% of attempts</div>
                </div>
                <div class="kpi<?= $travelCount24 + $regionCount24 === 0 ? ' zero' : '' ?>" style="--kpi-color: var(--high)">
                    <div class="kpi-label"><?= icon('plane', 14) ?> Travel anomalies</div>
                    <div class="kpi-value"><?= $travelCount24 + $regionCount24 ?></div>
                    <div class="kpi-sub"><?= $travelCount24 ?> impossible &middot; <?= $regionCount24 ?> region change</div>
                </div>
                <div class="kpi<?= count($deviceRows) === 0 ? ' zero' : '' ?>" style="--kpi-color: #8b5cf6">
                    <div class="kpi-label"><?= icon('key', 14) ?> MFA device changes</div>
                    <div class="kpi-value"><?= count($deviceRows) ?></div>
                    <div class="kpi-sub">added or removed</div>
                </div>
            </div>

            <div class="grid-2">
                <section class="panel" aria-labelledby="risk-users-title">
                    <div class="panel-head">
                        <h2 id="risk-users-title"><?= icon('users', 18) ?> Users at risk</h2>
                        <span class="hint">Scored over the last 24 hours</span>
                    </div>
                    <?php if (empty($riskUsers)): ?>
                        <div class="empty">No users are currently above the risk threshold.</div>
                    <?php else: ?>
                    <div class="table-wrapper scroll-y">
                        <table>
                            <thead><tr><th>User</th><th>Risk</th><th>Score</th><th class="col-signals">Signals</th><th class="col-when">Last activity</th></tr></thead>
                            <tbody>
                            <?php foreach ($riskUsers as $ru): $signals = json_decode($ru['signals'] ?? '[]', true) ?: []; ?>
                                <tr>
                                    <td><a class="highlight-upn" href="user_ip_report.php?user=<?= urlencode($ru['user_principal_name']) ?>"><?= h($ru['user_principal_name']) ?></a></td>
                                    <td><?= tierBadge($ru['tier']) ?></td>
                                    <td><div class="meter tier-<?= h($ru['tier']) ?>"><div class="meter-track"><div class="meter-fill" style="width: <?= (int)$ru['score'] ?>%"></div></div><b><?= (int)$ru['score'] ?></b></div></td>
                                    <td class="col-signals">
                                        <div class="chips">
                                            <?php foreach (array_slice($signals, 0, 3) as $sig): ?>
                                                <span class="chip<?= $sig['weight'] >= 50 ? ' strong' : '' ?>"><?= h($sig['label']) ?><?= $sig['count'] > 1 ? ' ×' . (int)$sig['count'] : '' ?></span>
                                            <?php endforeach; ?>
                                            <?php if (count($signals) > 3): ?><span class="chip">+<?= count($signals) - 3 ?> more</span><?php endif; ?>
                                        </div>
                                    </td>
                                    <td class="col-when"><small><?= utcShort($ru['last_event_at']) ?></small></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php endif; ?>
                </section>

                <section class="panel" aria-labelledby="feed-title">
                    <div class="panel-head">
                        <h2 id="feed-title"><?= icon('zap', 18) ?> Latest risk signals</h2>
                        <a href="#risk" class="hint" data-open-tab="risk">View all</a>
                    </div>
                    <?php if (empty($riskEvents)): ?>
                        <div class="empty">No risk signals in the last 7 days.</div>
                    <?php else: ?>
                    <ul class="feed">
                        <?php foreach (array_slice($riskEvents, 0, 20) as $ev):
                            $sev = App\RiskScorer::severityForWeight((int)$ev['weight']);
                            $label = App\RiskScorer::SIGNALS[$ev['signal_code']]['label'] ?? $ev['signal_code']; ?>
                            <li>
                                <span class="dot tier-<?= $sev ?>" title="<?= ucfirst($sev) ?>"></span>
                                <div>
                                    <div class="title"><?= h($label) ?> &middot; <span class="muted"><?= h($ev['user_principal_name']) ?></span></div>
                                    <div class="desc"><?= h($ev['description']) ?></div>
                                    <div class="when"><?= utcShort($ev['occurred_at']) ?></div>
                                </div>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                    <?php endif; ?>
                </section>
            </div>

            <div class="grid-2">
                <section class="panel" aria-labelledby="chart-title">
                    <div class="panel-head">
                        <h2 id="chart-title"><?= icon('activity', 18) ?> Sign-ins per hour</h2>
                        <div class="legend"><span><i style="background: var(--accent)"></i>Successful</span><span><i style="background: var(--critical)"></i>Failed</span></div>
                    </div>
                    <div class="panel-body">
                        <div class="chart" role="img" aria-label="Sign-ins per hour over the last 24 hours: <?= number_format((int)$stats['total']) ?> total, <?= number_format((int)$stats['failed']) ?> failed">
                            <?php foreach ($hourly as $hourKey => $bucket): ?>
                                <div class="col" data-hour="<?= h($hourKey) ?>:00:00 UTC" data-ok="<?= $bucket['ok'] ?>" data-fail="<?= $bucket['fail'] ?>">
                                    <div class="seg-fail" style="height: <?= round($bucket['fail'] / $hourlyMax * 100, 1) ?>%"></div>
                                    <div class="seg-ok" style="height: <?= round($bucket['ok'] / $hourlyMax * 100, 1) ?>%"></div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <?php $hourKeys = array_keys($hourly); ?>
                        <div class="chart-axis">
                            <span class="utc-hour" data-timestamp="<?= h($hourKeys[0]) ?>:00:00 UTC"></span>
                            <span class="utc-hour" data-timestamp="<?= h($hourKeys[8]) ?>:00:00 UTC"></span>
                            <span class="utc-hour" data-timestamp="<?= h($hourKeys[16]) ?>:00:00 UTC"></span>
                            <span>Now</span>
                        </div>
                    </div>
                </section>

                <section class="panel" aria-labelledby="countries-title">
                    <div class="panel-head">
                        <h2 id="countries-title"><?= icon('globe', 18) ?> Top sign-in countries</h2>
                        <span class="hint">Successful, 24h</span>
                    </div>
                    <div class="panel-body">
                        <?php if (empty($topCountries)): ?>
                            <div class="empty">No sign-ins in the last 24 hours.</div>
                        <?php else: ?>
                        <ul class="barlist">
                            <?php foreach ($topCountries as $c): ?>
                                <li><span><?= h($c['country']) ?></span><b><?= number_format((int)$c['c']) ?></b>
                                    <div class="track"><div class="fill" style="width: <?= round($c['c'] / $topCountryMax * 100) ?>%"></div></div></li>
                            <?php endforeach; ?>
                        </ul>
                        <?php endif; ?>
                    </div>
                </section>
            </div>

            <section class="panel" aria-label="Details">
                <div class="tabs" role="tablist">
                    <button class="tab" role="tab" id="tab-risk" aria-controls="panel-risk" aria-selected="true" data-tab="risk"><?= icon('zap', 16) ?> Risk events <span class="count"><?= count($riskEvents) ?></span></button>
                    <button class="tab" role="tab" id="tab-travel" aria-controls="panel-travel" aria-selected="false" data-tab="travel"><?= icon('plane', 16) ?> Impossible travel <span class="count"><?= count($travelRows) ?></span></button>
                    <button class="tab" role="tab" id="tab-region" aria-controls="panel-region" aria-selected="false" data-tab="region"><?= icon('pin', 16) ?> Region changes <span class="count"><?= count($regionRows) ?></span></button>
                    <button class="tab" role="tab" id="tab-mfa" aria-controls="panel-mfa" aria-selected="false" data-tab="mfa"><?= icon('key', 16) ?> MFA changes <span class="count"><?= count($deviceRows) ?></span></button>
                    <button class="tab" role="tab" id="tab-signins" aria-controls="panel-signins" aria-selected="false" data-tab="signins"><?= icon('list', 16) ?> Sign-ins (24h) <span class="count"><?= number_format((int)$stats['total']) ?></span></button>
                    <button class="tab" role="tab" id="tab-whitelist" aria-controls="panel-whitelist" aria-selected="false" data-tab="whitelist"><?= icon('shield', 16) ?> IP whitelist <span class="count"><?= count($whitelistRows) ?></span></button>
                    <button class="tab" role="tab" id="tab-tools" aria-controls="panel-tools" aria-selected="false" data-tab="tools"><?= icon('sliders', 16) ?> Tools &amp; help</button>
                </div>

                <div class="tab-panel" role="tabpanel" id="panel-risk" aria-labelledby="tab-risk">
                    <div class="table-wrapper scroll-y">
                        <table>
                            <thead><tr><th>Severity</th><th>Signal</th><th>User</th><th>Detail</th><th>IP</th><th>When</th></tr></thead>
                            <tbody>
                            <?php foreach ($riskEvents as $ev):
                                $sev = App\RiskScorer::severityForWeight((int)$ev['weight']); ?>
                                <tr>
                                    <td><?= tierBadge($sev) ?></td>
                                    <td><strong><?= h(App\RiskScorer::SIGNALS[$ev['signal_code']]['label'] ?? $ev['signal_code']) ?></strong></td>
                                    <td class="highlight-upn"><?= h($ev['user_principal_name']) ?></td>
                                    <td><?= h($ev['description']) ?></td>
                                    <td class="mono"><?= h($ev['ip_address']) ?></td>
                                    <td class="nowrap"><?= utcShort($ev['occurred_at']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                            <?php if (empty($riskEvents)): ?><tr><td colspan="6" class="empty">No risk signals in the last 7 days.</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="tab-panel" role="tabpanel" id="panel-travel" aria-labelledby="tab-travel" hidden>
                    <div class="table-wrapper scroll-y">
                        <table>
                            <thead><tr><th>User</th><th>Status</th><th>Travel details</th><th>Speed (km/h)</th><th>Email sent</th></tr></thead>
                            <tbody>
                            <?php foreach ($travelRows as $row): ?>
                                <tr>
                                    <td class="highlight-upn"><?= h($row['user_principal_name']) ?></td>
                                    <td><?= str_starts_with($row['status'], 'Failure') ? '<span class="badge fail">Failed</span>' : '<span class="badge ok">Success</span>' ?></td>
                                    <td class="travel-details">
                                        <?php if ($row['p_time']): ?>
                                        <div><strong>FROM</strong> <?= h(($row['p_city'] ?? 'N/A') . ', ' . ($row['p_country'] ?? 'N/A')) ?><small><?= h($row['p_ip']) ?> &middot; <?= utcTime($row['p_time']) ?></small></div>
                                        <?php endif; ?>
                                        <div><strong>TO</strong> <?= h(($row['city'] ?? 'N/A') . ', ' . ($row['country'] ?? 'N/A')) ?><small><?= h($row['ip_address']) ?> &middot; <?= utcTime($row['login_time']) ?></small></div>
                                    </td>
                                    <td class="highlight-speed"><?= number_format(round($row['travel_speed_kph'])) ?></td>
                                    <td class="email-status"><?= $row['email_sent_at'] ? '<span class="email-status-yes">Sent</span><small>' . utcTime($row['email_sent_at']) . '</small>' : '<span class="email-status-no">No</span>' ?></td>
                                </tr>
                            <?php endforeach; ?>
                            <?php if (empty($travelRows)): ?><tr><td colspan="5" class="empty">No impossible travel alerts found.</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="tab-panel" role="tabpanel" id="panel-region" aria-labelledby="tab-region" hidden>
                    <div class="table-wrapper scroll-y">
                        <table>
                            <thead><tr><th>User</th><th>Status</th><th>Travel details</th><th>Email sent</th></tr></thead>
                            <tbody>
                            <?php foreach ($regionRows as $row): ?>
                                <tr>
                                    <td class="highlight-upn"><?= h($row['user_principal_name']) ?></td>
                                    <td><?= str_starts_with($row['status'], 'Failure') ? '<span class="badge fail">Failed</span>' : '<span class="badge ok">Success</span>' ?></td>
                                    <td class="travel-details">
                                        <?php if ($row['p_time']): ?>
                                        <div><strong>FROM</strong> <?= h(($row['p_region'] ?? 'N/A') . ' (' . ($row['p_country'] ?? 'N/A') . ')') ?><small><?= h($row['p_ip']) ?> &middot; <?= utcTime($row['p_time']) ?></small></div>
                                        <?php endif; ?>
                                        <div><strong>TO</strong> <?= h(($row['region'] ?? 'N/A') . ' (' . ($row['country'] ?? 'N/A') . ')') ?><small><?= h($row['ip_address']) ?> &middot; <?= utcTime($row['login_time']) ?></small></div>
                                    </td>
                                    <td class="email-status"><?= $row['email_sent_at'] ? '<span class="email-status-yes">Sent</span><small>' . utcTime($row['email_sent_at']) . '</small>' : '<span class="email-status-no">No</span>' ?></td>
                                </tr>
                            <?php endforeach; ?>
                            <?php if (empty($regionRows)): ?><tr><td colspan="4" class="empty">No region change alerts found.</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="tab-panel" role="tabpanel" id="panel-mfa" aria-labelledby="tab-mfa" hidden>
                    <div class="table-wrapper">
                        <table>
                            <thead><tr><th>User</th><th>Device</th><th>Change</th><th>Time</th></tr></thead>
                            <tbody>
                            <?php foreach ($deviceRows as $row): ?>
                                <tr>
                                    <td class="highlight-upn"><?= h($row['user_principal_name']) ?></td>
                                    <td><strong><?= h($row['device_display_name']) ?></strong></td>
                                    <td><?= strtolower($row['change_type']) === 'added' ? '<span class="badge ok">Added</span>' : '<span class="badge fail">Removed</span>' ?></td>
                                    <td><?= utcTime($row['change_time']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                            <?php if (empty($deviceRows)): ?><tr><td colspan="4" class="empty">No authentication device changes in the last 24 hours.</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="tab-panel" role="tabpanel" id="panel-signins" aria-labelledby="tab-signins" hidden>
                    <div class="toolbar">
                        <input type="search" id="signin-filter" placeholder="Filter by user, IP, location, app…" aria-label="Filter sign-ins">
                        <span class="muted" id="signin-count"><?= count($signinRows) ?> shown</span>
                        <?php if ((int)$stats['total'] > $signinLimit): ?><span class="muted">Newest <?= number_format($signinLimit) ?> of <?= number_format((int)$stats['total']) ?> &mdash; use an export for the full list.</span><?php endif; ?>
                    </div>
                    <div class="table-wrapper scroll-y">
                        <table id="signin-table">
                            <thead><tr><th>User</th><th>Time</th><th>Status</th><th>IP address</th><th>Location</th><th>App</th><th>Device</th></tr></thead>
                            <tbody>
                            <?php foreach ($signinRows as $row): $failed = str_starts_with($row['status'], 'Failure'); ?>
                                <tr<?= $failed ? ' class="failure-row"' : '' ?>>
                                    <td class="highlight-upn"><?= h($row['user_principal_name']) ?></td>
                                    <td><?= utcTime($row['login_time']) ?></td>
                                    <td class="<?= $failed ? 'failure-text' : '' ?>"><?= h($row['status']) ?></td>
                                    <td class="mono"><?= h($row['ip_address']) ?></td>
                                    <td><?= h(trim(($row['city'] ?? '') . ', ' . ($row['country'] ?? ''), ', ')) ?></td>
                                    <td><?= h($row['app_display_name']) ?></td>
                                    <td><?= h(trim(($row['device_os'] ?? '') . ' ' . ($row['device_browser'] ?? ''))) ?></td>
                                </tr>
                            <?php endforeach; ?>
                            <?php if (empty($signinRows)): ?><tr><td colspan="7" class="empty">No sign-ins in the last 24 hours.</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="tab-panel" role="tabpanel" id="panel-whitelist" aria-labelledby="tab-whitelist" hidden>
                    <div class="panel-body">
                        <form method="POST" action="<?= BASE_PATH ?>" class="whitelist-form">
                            <input type="text" name="ip_address" placeholder="IP address" required aria-label="IP address">
                            <input type="text" name="note" placeholder="Note (e.g. Corporate VPN)" aria-label="Note">
                            <button type="submit" name="add_whitelist" class="btn-primary">Add to whitelist</button>
                        </form>
                        <div class="table-wrapper" style="border: 1px solid var(--border); border-radius: 8px;">
                            <table>
                                <thead><tr><th>IP address</th><th>Note</th><th>Added</th><th></th></tr></thead>
                                <tbody>
                                <?php foreach ($whitelistRows as $row): ?>
                                    <tr>
                                        <td class="mono"><?= h($row['ip_address']) ?></td>
                                        <td><?= h($row['note']) ?></td>
                                        <td><?= utcTime($row['created_at']) ?></td>
                                        <td><form method="POST" action="<?= BASE_PATH ?>" style="margin:0;"><input type="hidden" name="whitelist_id" value="<?= (int)$row['id'] ?>"><button type="submit" name="delete_whitelist" class="delete-button">Remove</button></form></td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php if (empty($whitelistRows)): ?><tr><td colspan="4" class="empty">No IP addresses have been whitelisted.</td></tr><?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="tab-panel" role="tabpanel" id="panel-tools" aria-labelledby="tab-tools" hidden>
                    <div class="panel-body">
                        <div class="tool-grid">
                            <div class="tool">
                                <h3>Export data</h3>
                                <p>Download alerts or sign-ins as CSV.</p>
                                <form method="POST" action="<?= BASE_PATH ?>" class="export-form">
                                    <select name="export_type" aria-label="Export type">
                                        <option value="alerts_24hr">Alerts (last 24 hours)</option>
                                        <option value="alerts_all">Alerts (all time)</option>
                                        <option value="signins_24hr">Sign-ins (last 24 hours)</option>
                                        <option value="signins_7day">Sign-ins (last 7 days)</option>
                                        <option value="signins_30day">Sign-ins (last 30 days)</option>
                                        <option value="signins_all">Sign-ins (all time)</option>
                                    </select>
                                    <button type="submit" name="export_data" class="btn-ghost"><?= icon('download', 16) ?> Download</button>
                                </form>
                            </div>
                            <div class="tool">
                                <h3>API token</h3>
                                <p>Bearer token for <code>/api/reports.php</code>.</p>
                                <?php if (!empty($_ENV['API_TOKEN'])): ?>
                                    <div><code class="token" id="api-token" data-token="<?= h($_ENV['API_TOKEN']) ?>">••••••••••••••••••••</code></div>
                                    <button type="button" class="btn-ghost" id="toggle-token"><?= icon('lock', 16) ?> Reveal</button>
                                <?php else: ?>
                                    <p><em>Not generated yet.</em></p>
                                <?php endif; ?>
                                <form method="POST" action="<?= BASE_PATH ?>" style="display: inline-block;">
                                    <button type="submit" name="generate_api_token" class="btn-ghost"><?= empty($_ENV['API_TOKEN']) ? 'Generate' : 'Regenerate' ?></button>
                                </form>
                            </div>
                            <div class="tool">
                                <h3>Reprocess all logs</h3>
                                <p>Recomputes every travel flag from stored sign-ins. This can take a long time.</p>
                                <form method="POST" action="<?= BASE_PATH ?>" onsubmit="return confirm('WARNING: This will re-process all existing logs and may take a long time. Are you sure you want to continue?');">
                                    <button type="submit" name="reprocess_logs" class="btn-warn">Reprocess all logs</button>
                                </form>
                            </div>
                        </div>

                        <details class="help-section">
                            <summary>How risk scoring works</summary>
                            <div>
                                <p>Each sign-in is checked against what is normal for that user (countries, ISPs, devices and apps seen on at least two separate days) and against patterns across recent sign-ins. Every match records a weighted <em>risk signal</em>. A user's score is the sum of their signals over the last 24 hours, capped at 100.</p>
                                <h4>Tiers</h4>
                                <ul>
                                    <?php foreach ($tierNames as $tier): ?>
                                        <li><strong><?= ucfirst($tier) ?></strong> &mdash; score of <?= $tierThresholds[$tier] ?> or more<?= $tier === 'critical' ? ', or an MFA-fatigue success / MFA change next to an anomalous sign-in' : '' ?></li>
                                    <?php endforeach; ?>
                                </ul>
                                <p>Thresholds and weights can be changed in <code>secrets.php</code> (<code>RISK_TIER_*</code>, <code>RISK_WEIGHTS</code>). Scoring only informs this dashboard; it does not change which emails are sent.</p>
                                <h4>Signals and default weights</h4>
                                <div class="table-wrapper">
                                    <table>
                                        <thead><tr><th>Signal</th><th>Weight</th></tr></thead>
                                        <tbody>
                                        <?php foreach (App\RiskScorer::SIGNALS as $code => $def): ?>
                                            <tr><td><?= h($def['label']) ?> <small class="mono"><?= h($code) ?></small></td><td><?= (int)$def['weight'] ?></td></tr>
                                        <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </details>

                        <details class="help-section">
                            <summary>How alerts and emails work</summary>
                            <div>
                                <h4>Alert types</h4>
                                <ul>
                                    <li><strong>Authentication device change:</strong> a user adds or removes an MFA device. An email is always sent.</li>
                                    <li><strong>Impossible travel:</strong> speed between two sign-ins in 24 hours exceeds <code>IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD</code>. Shown for every case; emailed only if both sign-ins succeeded and neither IP is whitelisted.</li>
                                    <li><strong>Region change:</strong> successful sign-ins in two different states or provinces within 24 hours. Emailed only if the distance exceeds <code>REGION_CHANGE_IGNORE_KM</code> and neither IP is whitelisted.</li>
                                </ul>
                                <h4>Email digest</h4>
                                <p>One consolidated email is sent at the end of each run. The &ldquo;Email sent&rdquo; column shows whether a specific alert was included.</p>
                                <h4>IP whitelist</h4>
                                <p>Whitelisted IPs are still logged and shown, but are suppressed from emails and from location-based risk signals. Whitelist static office, data-centre and company VPN addresses; do not whitelist public VPN services, dynamic addresses or anything you do not control.</p>
                            </div>
                        </details>
                    </div>
                </div>
                <noscript><style>.tab-panel[hidden] { display: block !important; }</style></noscript>
            </section>
        </main>
    </div>
<?php else: ?>
    <div class="container">
        <div class="login-box">
            <div class="login-brand"><?= icon('shield', 24) ?> Entra Monitor</div>
            <form method="POST" action="<?= BASE_PATH ?>">
                <h2>Administrator sign in</h2>
                <?php if ($errorMessage): ?>
                    <p class="error-message"><?= h($errorMessage) ?></p>
                <?php endif; ?>
                <div class="input-group"><label for="username">Username</label><input type="text" id="username" name="username" autocomplete="username" required></div>
                <div class="input-group"><label for="password">Password</label><input type="password" id="password" name="password" autocomplete="current-password" required></div>
                <div class="cf-turnstile" data-sitekey="<?= h($_ENV['TURNSTILE_SITE_KEY'] ?? '') ?>"></div>
                <button type="submit" name="login" class="btn-primary">Sign in</button>
            </form>
        </div>
    </div>
<?php endif; ?>

    <script>
        document.addEventListener('DOMContentLoaded', function () {
            var fullFormat = { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true };

            document.querySelectorAll('.utc-time').forEach(function (el) {
                var d = new Date(el.dataset.timestamp);
                el.textContent = isNaN(d.getTime()) ? el.textContent : d.toLocaleString(undefined, fullFormat);
            });
            document.querySelectorAll('.utc-short').forEach(function (el) {
                var d = new Date(el.dataset.timestamp);
                if (!isNaN(d.getTime())) el.textContent = d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
            });
            document.querySelectorAll('.utc-hour').forEach(function (el) {
                var d = new Date(el.dataset.timestamp);
                if (!isNaN(d.getTime())) el.textContent = d.toLocaleTimeString(undefined, { hour: 'numeric' });
            });
            var generated = document.getElementById('generated');
            if (generated) {
                var g = new Date(generated.dataset.timestamp);
                if (!isNaN(g.getTime())) generated.textContent = 'updated ' + g.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
            }
            document.querySelectorAll('.chart .col').forEach(function (col) {
                var d = new Date(col.dataset.hour);
                var label = isNaN(d.getTime()) ? '' : d.toLocaleTimeString(undefined, { hour: 'numeric' }) + ': ';
                col.title = label + col.dataset.ok + ' successful, ' + col.dataset.fail + ' failed';
            });

            // Tabs
            var tabs = Array.prototype.slice.call(document.querySelectorAll('.tab'));
            function openTab(name) {
                var found = false;
                tabs.forEach(function (tab) {
                    var on = tab.dataset.tab === name;
                    found = found || on;
                    tab.setAttribute('aria-selected', on ? 'true' : 'false');
                    document.getElementById('panel-' + tab.dataset.tab).hidden = !on;
                });
                return found;
            }
            tabs.forEach(function (tab) {
                tab.addEventListener('click', function () {
                    openTab(tab.dataset.tab);
                    history.replaceState(null, '', '#' + tab.dataset.tab);
                });
            });
            document.querySelectorAll('[data-open-tab]').forEach(function (link) {
                link.addEventListener('click', function (e) {
                    e.preventDefault();
                    openTab(link.dataset.openTab);
                    history.replaceState(null, '', '#' + link.dataset.openTab);
                    document.querySelector('.tabs').scrollIntoView({ behavior: 'smooth', block: 'start' });
                });
            });
            if (tabs.length && location.hash) openTab(location.hash.slice(1));

            // Sign-in filter
            var filter = document.getElementById('signin-filter');
            if (filter) {
                var rows = document.querySelectorAll('#signin-table tbody tr');
                var counter = document.getElementById('signin-count');
                filter.addEventListener('input', function () {
                    var q = filter.value.trim().toLowerCase(), shown = 0;
                    rows.forEach(function (row) {
                        var match = !q || row.textContent.toLowerCase().indexOf(q) !== -1;
                        row.style.display = match ? '' : 'none';
                        if (match) shown++;
                    });
                    counter.textContent = shown + ' shown';
                });
            }

            // API token reveal
            var toggle = document.getElementById('toggle-token');
            if (toggle) {
                toggle.addEventListener('click', function () {
                    var el = document.getElementById('api-token');
                    var hidden = el.dataset.revealed !== '1';
                    el.textContent = hidden ? el.dataset.token : '••••••••••••••••••••';
                    el.dataset.revealed = hidden ? '1' : '0';
                    toggle.lastChild.textContent = hidden ? ' Hide' : ' Reveal';
                });
            }
        });
    </script>
</body>
</html>
