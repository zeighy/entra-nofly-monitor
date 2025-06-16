<?php
define('BASE_PATH', '/nofly-monitor/public/index.php');

// --- Session Handling ---
$session_path = __DIR__ . '/../sessions';
if (!is_dir($session_path)) {
    if (!@mkdir($session_path, 0777, true) && !is_dir($session_path)) {
         die("FATAL ERROR: Could not create session directory at '$session_path'. Please verify that the parent directory is writable by the web server user ('nobody').");
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
    putenv("$key=$value");
}

use App\Auth;
use App\Database;

$auth = new Auth();
$db = Database::getInstance();
$errorMessage = '';
$infoMessage = '';

$alertsStmt = null;
$regionChangeStmt = null; // New statement for region changes
$logsStmt = null;

if (isset($_SESSION['info_message'])) {
    $infoMessage = $_SESSION['info_message'];
    unset($_SESSION['info_message']); 
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    if ($auth->login($_POST['username'], $_POST['password'])) {
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
    if (isset($_GET['export'])) {
        $filename = "export_" . $_GET['export'] . "_" . date('Y-m-d') . ".csv";
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        $output = fopen('php://output', 'w');
        $escape_char = '\\';
        if ($_GET['export'] === 'alerts') {
            fputcsv($output, ['User', 'Status', 'From Location', 'From Time', 'To Location', 'To Time', 'Speed (km/h)'], ',', '"', $escape_char);
            $stmt = $db->query("SELECT * FROM login_logs WHERE is_impossible_travel = 1 ORDER BY login_time DESC");
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $prevStmt = $db->prepare("SELECT * FROM login_logs WHERE id = ?");
                $prevStmt->execute([$row['previous_log_id']]);
                $prevRow = $prevStmt->fetch(PDO::FETCH_ASSOC);
                $csvRow = [$row['user_principal_name'], $row['status'], ($prevRow['city'] ?? '') . ', ' . ($prevRow['country'] ?? ''), $prevRow['login_time'], ($row['city'] ?? '') . ', ' . ($row['country'] ?? ''), $row['login_time'], round($row['travel_speed_kph'])];
                fputcsv($output, $csvRow, ',', '"', $escape_char);
            }
        } elseif ($_GET['export'] === 'failures') {
            fputcsv($output, ['User', 'Login Time (UTC)', 'Status', 'IP Address', 'Location'], ',', '"', $escape_char);
            $stmt = $db->query("SELECT user_principal_name, login_time, status, ip_address, city, country FROM login_logs WHERE status != 'Success' ORDER BY login_time DESC");
             while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $row['location'] = ($row['city'] ?? '') . ', ' . ($row['country'] ?? '');
                unset($row['city'], $row['country']);
                fputcsv($output, $row, ',', '"', $escape_char);
            }
        }
        fclose($output);
        exit;
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
    
    $alertsStmt = $db->query("SELECT * FROM login_logs WHERE is_impossible_travel = 1 ORDER BY login_time DESC LIMIT 100");
    $regionChangeStmt = $db->query("SELECT * FROM login_logs WHERE is_region_change = 1 ORDER BY login_time DESC LIMIT 100");
    $logsStmt = $db->query("SELECT * FROM login_logs ORDER BY login_time DESC LIMIT 200");
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra Impossible Travel Monitor</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Entra Impossible Travel Monitor</h1>
            <?php if ($auth->check()): ?>
                <div class="user-info">
                    Welcome, <strong><?= htmlspecialchars($auth->getUsername()) ?></strong> | <a href="<?= BASE_PATH ?>?logout=1">Logout</a>
                </div>
            <?php endif; ?>
        </header>

        <?php if ($auth->check()): ?>
            <main>
                <?php if ($infoMessage): ?>
                <div class="info-message"><?= htmlspecialchars($infoMessage) ?></div>
                <?php endif; ?>

                <div class="action-bar">
                    <a href="<?= BASE_PATH ?>?trigger=background" class="action-button">Manually Trigger Sync</a>
                    <a href="<?= BASE_PATH ?>?export=alerts" class="action-button">Export Alerts</a>
                    <a href="<?= BASE_PATH ?>?export=failures" class="action-button">Export Failed Sign-ins</a>
                </div>

                <section class="alerts">
                    <h2><span class="icon">&#9888;</span> Impossible Travel Alerts</h2>
                    <div class="table-wrapper">
                        <table>
                            <thead><tr><th>User</th><th>Status</th><th>Travel Details</th><th>Speed (km/h)</th></tr></thead>
                            <tbody>
                                <?php if($alertsStmt): while ($row = $alertsStmt->fetch()): ?>
                                <?php
                                    $prevStmt = $db->prepare("SELECT * FROM login_logs WHERE id = ?");
                                    $prevStmt->execute([$row['previous_log_id']]);
                                    $prevRow = $prevStmt->fetch();
                                ?>
                                <tr class="alert-row">
                                    <td><?= htmlspecialchars($row['user_principal_name']) ?></td>
                                    <td class="<?= str_starts_with($row['status'], 'Failure') ? 'failure-text' : '' ?>"><?= htmlspecialchars($row['status']) ?></td>
                                    <td class="travel-details">
                                        <?php if ($prevRow): ?>
                                        <div><strong>From:</strong> <?= htmlspecialchars(($prevRow['city'] ?? 'N/A') . ', ' . ($prevRow['country'] ?? 'N/A')) ?><br><small>(<?= htmlspecialchars($prevRow['ip_address']) ?> at <?= htmlspecialchars($prevRow['login_time']) ?>)</small></div>
                                        <?php endif; ?>
                                        <div><strong>To:</strong> <?= htmlspecialchars(($row['city'] ?? 'N/A') . ', ' . ($row['country'] ?? 'N/A')) ?><br><small>(<?= htmlspecialchars($row['ip_address']) ?> at <?= htmlspecialchars($row['login_time']) ?>)</small></div>
                                    </td>
                                    <td><?= round($row['travel_speed_kph']) ?></td>
                                </tr>
                                <?php endwhile; if($alertsStmt && $alertsStmt->rowCount() === 0): ?>
                                    <tr><td colspan="4">No impossible travel alerts found.</td></tr>
                                <?php endif; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="region-changes">
                    <h2><span class="icon">&#127758;</span> Region Change Alerts</h2>
                    <div class="table-wrapper">
                        <table>
                            <thead><tr><th>User</th><th>Status</th><th>Travel Details</th></tr></thead>
                            <tbody>
                                <?php if($regionChangeStmt): while ($row = $regionChangeStmt->fetch()): ?>
                                <?php
                                    $prevStmt = $db->prepare("SELECT * FROM login_logs WHERE id = ?");
                                    $prevStmt->execute([$row['previous_log_id']]);
                                    $prevRow = $prevStmt->fetch();
                                ?>
                                <tr class="region-change-row">
                                    <td><?= htmlspecialchars($row['user_principal_name']) ?></td>
                                    <td class="<?= str_starts_with($row['status'], 'Failure') ? 'failure-text' : '' ?>"><?= htmlspecialchars($row['status']) ?></td>
                                    <td class="travel-details">
                                        <?php if ($prevRow): ?>
                                        <div>
                                            <strong>From:</strong> <?= htmlspecialchars($prevRow['region'] ?? 'N/A') ?> (<?= htmlspecialchars($prevRow['country'] ?? 'N/A') ?>)<br>
                                            <small>(<?= htmlspecialchars($prevRow['ip_address']) ?> at <?= htmlspecialchars($prevRow['login_time']) ?>)</small>
                                        </div>
                                        <?php endif; ?>
                                        <div>
                                            <strong>To:</strong> <?= htmlspecialchars($row['region'] ?? 'N/A') ?> (<?= htmlspecialchars($row['country'] ?? 'N/A') ?>)<br>
                                            <small>(<?= htmlspecialchars($row['ip_address']) ?> at <?= htmlspecialchars($row['login_time']) ?>)</small>
                                        </div>
                                    </td>
                                </tr>
                                <?php endwhile; if($regionChangeStmt && $regionChangeStmt->rowCount() === 0): ?>
                                    <tr><td colspan="3">No region change alerts found.</td></tr>
                                <?php endif; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="logs">
                    <h2><span class="icon">&#128195;</span> All Recent Login Logs</h2>
                    <div class="table-wrapper">
                         <table>
                            <thead><tr><th>User</th><th>Login Time (UTC)</th><th>Status</th><th>IP Address</th><th>Location</th></tr></thead>
                            <tbody>
                                <?php if($logsStmt): while ($row = $logsStmt->fetch()): ?>
                                <tr class="<?= str_starts_with($row['status'], 'Failure') ? 'failure-row' : '' ?>">
                                    <td><?= htmlspecialchars($row['user_principal_name']) ?></td>
                                    <td><?= $row['login_time'] ?></td>
                                    <td><?= htmlspecialchars($row['status']) ?></td>
                                    <td><?= htmlspecialchars($row['ip_address']) ?></td>
                                    <td><?= htmlspecialchars(($row['city'] ?? '') . ', ' . ($row['country'] ?? '')) ?></td>
                                </tr>
                                <?php endwhile; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </section>
            </main>
        <?php else: ?>
            <div class="login-box">
                <form method="POST" action="">
                    <h2>Admin Login</h2>
                    <?php if ($errorMessage): ?>
                        <p class="error-message"><?= $errorMessage ?></p>
                    <?php endif; ?>
                    <div class="input-group"><label for="username">Username</label><input type="text" id="username" name="username" required></div>
                    <div class="input-group"><label for="password">Password</label><input type="password" id="password" name="password" required></div>
                    <button type="submit" name="login">Sign In</button>
                </form>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
