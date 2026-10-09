<?php
define('BASE_PATH', 'failed_logins.php');

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

if (!$auth->check()) {
    header('Location: index.php');
    exit;
}

// Fetch the report data
// We only want users with failed logins in the last 7 days. We group by user_principal_name and calculate the metrics.
$stmt = $db->query("
    SELECT 
        user_principal_name,
        SUM(CASE WHEN status LIKE 'Failure%' AND login_time >= NOW() - INTERVAL 7 DAY THEN 1 ELSE 0 END) as failed_last_7_days,
        SUM(CASE WHEN status LIKE 'Failure%' AND login_time >= NOW() - INTERVAL 14 DAY AND login_time < NOW() - INTERVAL 7 DAY THEN 1 ELSE 0 END) as failed_prior_7_days,
        SUM(CASE WHEN status = 'Success' AND login_time >= NOW() - INTERVAL 7 DAY THEN 1 ELSE 0 END) as success_last_7_days
    FROM login_logs
    GROUP BY user_principal_name
    HAVING failed_last_7_days > 0
    ORDER BY failed_last_7_days DESC
");
$reportData = $stmt->fetchAll(PDO::FETCH_ASSOC);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Failed Logins Report - Entra Monitor</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<?php require_once __DIR__ . '/partials/nav.php'; render_nav('failed', $auth->getUsername()); ?>
    <div class="container">

        <main>
            <section class="report-section alerts">
                <h2><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path></svg> Users with Failed Logins (Last 7 Days)</h2>
                <div class="info-message">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    Showing users who had at least one failed login attempt in the last 7 days.
                </div>
                
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>Failed Logins (Last 7 Days)</th>
                                <th>Failed Logins (Prior 7 Days)</th>
                                <th>Successful Logins (Last 7 Days)</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($reportData)): ?>
                                <tr><td colspan="4">No failed logins found in the last 7 days.</td></tr>
                            <?php else: ?>
                                <?php foreach ($reportData as $row): ?>
                                    <tr>
                                        <td><a href="user_ip_report.php?user=<?= urlencode($row['user_principal_name']) ?>" class="highlight-upn" style="text-decoration: none; border-bottom: 2px solid transparent; transition: border-color 0.2s;" onmouseover="this.style.borderBottomColor='var(--primary-color)'" onmouseout="this.style.borderBottomColor='transparent'"><?= htmlspecialchars($row['user_principal_name']) ?></a></td>
                                        <td class="failure-text" style="font-size: 1.1rem;"><?= htmlspecialchars($row['failed_last_7_days']) ?></td>
                                        <td><?= htmlspecialchars($row['failed_prior_7_days']) ?></td>
                                        <td><span style="color: #059669; font-weight: bold;"><?= htmlspecialchars($row['success_last_7_days']) ?></span></td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </section>
        </main>
    </div>
</body>
</html>
