<?php
define('BASE_PATH', '/nofly-monitor/public/user_ip_report.php');

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

if (!$auth->check()) {
    header('Location: /nofly-monitor/public/index.php');
    exit;
}

$searchQuery = $_GET['q'] ?? '';
$selectedUser = $_GET['user'] ?? '';

$userOptions = [];
$ipReport = [];

if ($searchQuery) {
    $stmt = $db->prepare("SELECT DISTINCT user_principal_name FROM login_logs WHERE user_principal_name LIKE ? LIMIT 50");
    $stmt->execute(['%' . $searchQuery . '%']);
    $userOptions = $stmt->fetchAll(PDO::FETCH_COLUMN);
}

if ($selectedUser) {
    // Lookup IP addresses for the selected user in the last 30 days
    $stmt = $db->prepare("
        SELECT ip_address, COUNT(*) as occurrence_count, MAX(login_time) as last_seen,
               MAX(country) as country, MAX(region) as region, MAX(city) as city
        FROM login_logs 
        WHERE user_principal_name = ? AND login_time >= NOW() - INTERVAL 30 DAY
        GROUP BY ip_address
        ORDER BY occurrence_count DESC
    ");
    $stmt->execute([$selectedUser]);
    $ipReport = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User IP Report - Entra Monitor</title>
    <link rel="stylesheet" href="/nofly-monitor/public/style.css">
    <style>
        .search-form {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            align-items: center;
        }
        .search-form input[type="text"] {
            padding: 8px;
            width: 300px;
        }
        .user-options-list {
            list-style: none;
            padding: 0;
            margin-bottom: 30px;
        }
        .user-options-list li {
            margin-bottom: 10px;
        }
        .user-options-list a {
            text-decoration: none;
            color: #007bff;
            font-weight: bold;
        }
        .user-options-list a:hover {
            text-decoration: underline;
        }
        .report-section {
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>User IP Report (Last 30 Days)</h1>
            <div class="user-info">
                Welcome, <strong><?= htmlspecialchars($auth->getUsername()) ?></strong> | 
                <a href="/nofly-monitor/public/index.php">Back to Dashboard</a> | 
                <a href="/nofly-monitor/public/index.php?logout=1">Logout</a>
            </div>
        </header>

        <main>
            <section class="search-section">
                <h2>Search for a User</h2>
                <form method="GET" action="<?= htmlspecialchars(BASE_PATH) ?>" class="search-form">
                    <input type="text" name="q" placeholder="Enter full or partial username (e.g., john)" value="<?= htmlspecialchars($searchQuery) ?>" required>
                    <button type="submit">Search</button>
                </form>

                <?php if ($searchQuery && empty($userOptions) && !$selectedUser): ?>
                    <p>No users found matching "<?= htmlspecialchars($searchQuery) ?>".</p>
                <?php elseif ($searchQuery && !empty($userOptions) && !$selectedUser): ?>
                    <h3>Select a user:</h3>
                    <ul class="user-options-list">
                        <?php foreach ($userOptions as $user): ?>
                            <li><a href="<?= htmlspecialchars(BASE_PATH) ?>?user=<?= urlencode($user) ?>"><?= htmlspecialchars($user) ?></a></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </section>

            <?php if ($selectedUser): ?>
            <section class="report-section">
                <h2>IP Addresses for: <?= htmlspecialchars($selectedUser) ?></h2>
                <p>Showing activity for the last 30 days.</p>
                
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Occurrences</th>
                                <th>Last Seen (UTC)</th>
                                <th>Last Known Location</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($ipReport)): ?>
                                <tr><td colspan="4">No IP addresses found for this user in the last 30 days.</td></tr>
                            <?php else: ?>
                                <?php foreach ($ipReport as $row): ?>
                                    <tr>
                                        <td><?= htmlspecialchars($row['ip_address']) ?></td>
                                        <td><?= htmlspecialchars($row['occurrence_count']) ?></td>
                                        <td><span class="utc-time" data-timestamp="<?= htmlspecialchars($row['last_seen']) ?> UTC"><?= htmlspecialchars($row['last_seen']) ?> UTC</span></td>
                                        <td><?= htmlspecialchars(($row['city'] ?? '') . ', ' . ($row['region'] ?? '') . ', ' . ($row['country'] ?? '')) ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
                <div style="margin-top: 20px;">
                    <a href="<?= htmlspecialchars(BASE_PATH) ?>" class="action-button">New Search</a>
                </div>
            </section>
            <?php endif; ?>
        </main>
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
