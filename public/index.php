<?php
define('BASE_PATH', '/nofly-monitor/public/index.php');

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

// Initialize statement variables to null to prevent errors if not logged in
$alertsStmt = null;
$logsStmt = null;
$regionChangeStmt = null;
$whitelistStmt = null;
$deviceChangeStmt = null;

if (isset($_SESSION['info_message'])) {
    $infoMessage = $_SESSION['info_message'];
    unset($_SESSION['info_message']); 
}

// --- Login and Action Logic ---
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
    $deviceChangeStmt = $db->query("SELECT * FROM auth_device_changes WHERE change_time >= NOW() - INTERVAL 1 DAY ORDER BY change_time DESC");
    $logsStmt = $db->query("SELECT * FROM login_logs WHERE login_time >= NOW() - INTERVAL 1 DAY ORDER BY login_time DESC");
    $whitelistStmt = $db->query("SELECT * FROM ip_whitelist ORDER BY created_at DESC");
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra Impossible Travel Monitor</title>
    <link rel="stylesheet" href="/nofly-monitor/public/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Entra Impossible Travel Monitor</h1>
            <?php if ($auth->check()): ?>
                <div class="user-info">
                    Welcome, <strong><?= htmlspecialchars($auth->getUsername()) ?></strong> | 
                    <a href="user_ip_report.php">User IP Report</a> | 
                    <a href="<?= BASE_PATH ?>?logout=1">Logout</a>
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
                    <form method="POST" action="<?= BASE_PATH ?>" class="export-form">
                        <select name="export_type">
                            <option value="alerts_24hr">Export Alerts (Last 24 Hours)</option>
                            <option value="alerts_all">Export Alerts (All Time)</option>
                            <option value="signins_24hr">Export Sign-ins (Last 24 Hours)</option>
                            <option value="signins_7day">Export Sign-ins (Last 7 Days)</option>
                            <option value="signins_30day">Export Sign-ins (Last 30 Days)</option>
                            <option value="signins_all">Export Sign-ins (All Time)</option>
                        </select>
                        <button type="submit" name="export_data">Download Export</button>
                    </form>
                    <form method="POST" action="<?= BASE_PATH ?>" onsubmit="return confirm('WARNING: This will re-process all existing logs and may take a long time. Are you sure you want to continue?');">
                        <button type="submit" name="reprocess_logs" class="action-button reprocess-button">Reprocess All Logs</button>
                    </form>
                </div>

                <details class="help-section">
                    <summary>Help & Logic Explanation</summary>
                    <div>
                        <h4>How Alerts Are Processed</h4>
                        <p>This tool checks for three types of anomalies: Authentication Device Changes, Impossible Travel, and Region Changes.</p>
                        <ul>
                            <li><strong>Auth Device Change:</strong> This is flagged whenever a user adds or removes an MFA device (like an Authenticator App or Security Key). An email alert is always sent for these events.</li>
                            <li><strong>Impossible Travel:</strong> This is flagged if a user's login speed between any two locations in the last 24 hours exceeds the `IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD`. The UI will show all such events, but an email alert is only sent if **both** logins being compared were successful and neither IP is on the whitelist.</li>
                            <li><strong>Region Change:</strong> This is flagged for the UI if a user has successful logins in two different states or provinces within a 24-hour period. An email alert is only sent if the distance of this change is greater than the `REGION_CHANGE_IGNORE_KM` and neither IP is on the whitelist.</li>
                        </ul>
                        <h4>Email Notifications</h4>
                        <p>A single, consolidated email is sent at the end of each script run, summarizing all new incidents that meet the criteria for an email alert. The 'Email Sent' column in the alert tables on this page indicates if a specific alert was included in a digest and when it was sent.</p>
                        <h4>IP Whitelist</h4>
                        <p>You can add trusted IP addresses to the whitelist. Any alert originating from a whitelisted IP will still be logged for review in the UI, but it will be suppressed from the email alert digest to reduce noise.</p>
                        <strong>When should an IP be whitelisted?</strong>
                        <ul>
                            <li>Known static IPs for corporate offices, data centers, or remote servers.</li>
                            <li>Shared office spaces where internet traffic is centrally routed through a single public IP.</li>
                            <li>Company-managed VPN servers with a static egress IP address.</li>
                        </ul>
                        <strong>When should an IP NOT be whitelisted?</strong>
                        <ul>
                            <li>Publicly available VPN services (paid or free), as these IPs are shared and not trusted.</li>
                            <li>Office locations that use dynamic IP addresses that change frequently.</li>
                            <li>Any IP address that you do not fully control or trust.</li>
                        </ul>
                    </div>
                </details>

                <section class="device-changes">
                    <h2>Authentication Device Changes (Last 24 Hours)</h2>
                    <div class="table-wrapper">
                        <table>
                            <thead><tr><th>User</th><th>Device</th><th>Change</th><th>Time</th></tr></thead>
                            <tbody>
                                <?php if($deviceChangeStmt): while ($row = $deviceChangeStmt->fetch()): ?>
                                <tr class="device-change-row-<?= strtolower($row['change_type']) ?>">
                                    <td><?= htmlspecialchars($row['user_principal_name']) ?></td>
                                    <td><?= htmlspecialchars($row['device_display_name']) ?></td>
                                    <td><?= htmlspecialchars($row['change_type']) ?></td>
                                    <td><span class="utc-time" data-timestamp="<?= htmlspecialchars($row['change_time']) ?> UTC"><?= htmlspecialchars($row['change_time']) ?> UTC</span></td>
                                </tr>
                                <?php endwhile; if($deviceChangeStmt && $deviceChangeStmt->rowCount() === 0): ?>
                                    <tr><td colspan="4">No authentication device changes detected in the last 24 hours.</td></tr>
                                <?php endif; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="whitelist-manager">
                    <h2>IP Whitelist Management</h2>
                    <form method="POST" action="<?= BASE_PATH ?>" class="whitelist-form">
                        <input type="text" name="ip_address" placeholder="Enter IP Address" required>
                        <input type="text" name="note" placeholder="Note (e.g., Corporate VPN)">
                        <button type="submit" name="add_whitelist">Add to Whitelist</button>
                    </form>
                    <div class="table-wrapper">
                        <table>
                            <thead><tr><th>IP Address</th><th>Note</th><th>Added On</th><th>Action</th></tr></thead>
                            <tbody>
                                <?php if($whitelistStmt): while($row = $whitelistStmt->fetch()): ?>
                                <tr>
                                    <td><?= htmlspecialchars($row['ip_address']) ?></td>
                                    <td><?= htmlspecialchars($row['note']) ?></td>
                                    <td><span class="utc-time" data-timestamp="<?= htmlspecialchars($row['created_at']) ?> UTC"><?= htmlspecialchars($row['created_at']) ?> UTC</span></td>
                                    <td>
                                        <form method="POST" action="<?= BASE_PATH ?>" style="margin:0;"><input type="hidden" name="whitelist_id" value="<?= $row['id'] ?>"><button type="submit" name="delete_whitelist" class="delete-button">Delete</button></form>
                                    </td>
                                </tr>
                                <?php endwhile; if($whitelistStmt && $whitelistStmt->rowCount() === 0): ?>
                                    <tr><td colspan="4">No IP addresses have been whitelisted.</td></tr>
                                <?php endif; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="alerts">
                    <h2>Impossible Travel Alerts</h2>
                    <div class="table-wrapper">
                        <table>
                            <thead><tr><th>User</th><th>Status</th><th>Travel Details</th><th>Speed (km/h)</th><th>Email Sent</th></tr></thead>
                            <tbody>
                                <?php if($alertsStmt): while ($row = $alertsStmt->fetch()): ?>
                                <?php
                                    $prevStmt = $db->prepare("SELECT * FROM login_logs WHERE id = ?");
                                    $prevStmt->execute([$row['previous_log_id']]);
                                    $prevRow = $prevStmt->fetch();
                                    
                                    $emailStmt = $db->prepare("SELECT sent_at FROM email_alerts WHERE alert_log_id = ? AND compared_log_id = ? AND alert_type = 'impossible_travel'");
                                    $emailStmt->execute([$row['id'], $row['previous_log_id']]);
                                    $emailSent = $emailStmt->fetchColumn();
                                ?>
                                <tr class="alert-row">
                                    <td><?= htmlspecialchars($row['user_principal_name']) ?></td>
                                    <td class="<?= str_starts_with($row['status'], 'Failure') ? 'failure-text' : '' ?>"><?= htmlspecialchars($row['status']) ?></td>
                                    <td class="travel-details">
                                        <?php if ($prevRow): ?>
                                        <div><strong>From:</strong> <?= htmlspecialchars(($prevRow['city'] ?? 'N/A') . ', ' . ($prevRow['country'] ?? 'N/A')) ?><br><small>(<?= htmlspecialchars($prevRow['ip_address']) ?> at <span class="utc-time" data-timestamp="<?= htmlspecialchars($prevRow['login_time']) ?> UTC"><?= htmlspecialchars($prevRow['login_time']) ?> UTC</span>)</small></div>
                                        <?php endif; ?>
                                        <div><strong>To:</strong> <?= htmlspecialchars(($row['city'] ?? 'N/A') . ', ' . ($row['country'] ?? 'N/A')) ?><br><small>(<?= htmlspecialchars($row['ip_address']) ?> at <span class="utc-time" data-timestamp="<?= htmlspecialchars($row['login_time']) ?> UTC"><?= htmlspecialchars($row['login_time']) ?> UTC</span>)</small></div>
                                    </td>
                                    <td><?= round($row['travel_speed_kph']) ?></td>
                                    <td class="email-status"><?= $emailSent ? 'Yes<br><small class="utc-time" data-timestamp="' . htmlspecialchars($emailSent) . ' UTC">' . htmlspecialchars($emailSent) . ' UTC</small>' : 'No' ?></td>
                                </tr>
                                <?php endwhile; if($alertsStmt && $alertsStmt->rowCount() === 0): ?>
                                    <tr><td colspan="5">No impossible travel alerts found.</td></tr>
                                <?php endif; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="region-changes">
                    <h2>Region Change Alerts</h2>
                    <div class="table-wrapper">
                        <table>
                            <thead><tr><th>User</th><th>Status</th><th>Travel Details</th><th>Email Sent</th></tr></thead>
                            <tbody>
                                <?php if($regionChangeStmt): while ($row = $regionChangeStmt->fetch()): ?>
                                <?php
                                    $prevStmt = $db->prepare("SELECT * FROM login_logs WHERE id = ?");
                                    $prevStmt->execute([$row['previous_log_id']]);
                                    $prevRow = $prevStmt->fetch();

                                    $emailStmt = $db->prepare("SELECT sent_at FROM email_alerts WHERE alert_log_id = ? AND compared_log_id = ? AND alert_type = 'region_change'");
                                    $emailStmt->execute([$row['id'], $row['previous_log_id']]);
                                    $emailSent = $emailStmt->fetchColumn();
                                ?>
                                <tr class="region-change-row">
                                    <td><?= htmlspecialchars($row['user_principal_name']) ?></td>
                                    <td class="<?= str_starts_with($row['status'], 'Failure') ? 'failure-text' : '' ?>"><?= htmlspecialchars($row['status']) ?></td>
                                    <td class="travel-details">
                                        <?php if ($prevRow): ?>
                                        <div><strong>From:</strong> <?= htmlspecialchars($prevRow['region'] ?? 'N/A') ?> (<?= htmlspecialchars($prevRow['country'] ?? 'N/A') ?>)<br><small>(<?= htmlspecialchars($prevRow['ip_address']) ?> at <span class="utc-time" data-timestamp="<?= htmlspecialchars($prevRow['login_time']) ?> UTC"><?= htmlspecialchars($prevRow['login_time']) ?> UTC</span>)</small></div>
                                        <?php endif; ?>
                                        <div><strong>To:</strong> <?= htmlspecialchars($row['region'] ?? 'N/A') ?> (<?= htmlspecialchars($row['country'] ?? 'N/A') ?>)<br><small>(<?= htmlspecialchars($row['ip_address']) ?> at <span class="utc-time" data-timestamp="<?= htmlspecialchars($row['login_time']) ?> UTC"><?= htmlspecialchars($row['login_time']) ?> UTC</span>)</small></div>
                                    </td>
                                    <td class="email-status"><?= $emailSent ? 'Yes<br><small class="utc-time" data-timestamp="' . htmlspecialchars($emailSent) . ' UTC">' . htmlspecialchars($emailSent) . ' UTC</small>' : 'No' ?></td>
                                </tr>
                                <?php endwhile; if($regionChangeStmt && $regionChangeStmt->rowCount() === 0): ?>
                                    <tr><td colspan="4">No region change alerts found.</td></tr>
                                <?php endif; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="logs">
                    <h2>All Sign-in Logs (Last 24 Hours)</h2>
                    <div class="table-wrapper">
                         <table>
                            <thead><tr><th>User</th><th>Login Time</th><th>Status</th><th>IP Address</th><th>Location</th></tr></thead>
                            <tbody>
                                <?php if($logsStmt): while ($row = $logsStmt->fetch()): ?>
                                <tr class="<?= str_starts_with($row['status'], 'Failure') ? 'failure-row' : '' ?>">
                                    <td><?= htmlspecialchars($row['user_principal_name']) ?></td>
                                    <td><span class="utc-time" data-timestamp="<?= htmlspecialchars($row['login_time']) ?> UTC"><?= htmlspecialchars($row['login_time']) ?> UTC</span></td>
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
                <form method="POST" action="<?= BASE_PATH ?>">
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
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const timeElements = document.querySelectorAll('.utc-time');
            const options = {
                year: 'numeric', month: 'short', day: 'numeric',
                hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true
            };

            timeElements.forEach(function(element) {
                const utcTimestamp = element.dataset.timestamp;
                if (utcTimestamp) {
                    const localDate = new Date(utcTimestamp);
                    if (!isNaN(localDate.getTime())) {
                        element.textContent = localDate.toLocaleString(undefined, options);
                    } else {
                        element.textContent = 'Invalid Date';
                    }
                }
            });
        });
    </script>
</body>
</html>
