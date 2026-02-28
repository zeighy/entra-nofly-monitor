<?php
define('BASE_PATH', 'user_ip_report.php');

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
    header('Location: index.php');
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
    <link rel="stylesheet" href="style.css">
    <style>
        .search-form {
            display: flex;
            gap: 0;
            margin-bottom: 2rem;
            align-items: stretch;
            max-width: 600px;
        }
        .search-form input[type="text"] {
            width: 100%;
            border-right: none;
        }
        .search-form button {
            white-space: nowrap;
        }
        .user-options-list {
            list-style: none;
            padding: 0;
            margin-bottom: 2rem;
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 1rem;
        }
        .user-options-list li {
            margin: 0;
        }
        .user-options-list a {
            text-decoration: none;
            color: var(--primary-color);
            font-weight: 600;
            display: block;
            padding: 1rem;
            border: 1px solid var(--border-color);
            background: #f8fafc;
            transition: all 0.2s;
        }
        .user-options-list a:hover {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
            transform: translateY(-2px);
        }
        .report-section {
            margin-top: 2rem;
        }
        @media (max-width: 768px) {
            .search-form { flex-direction: column; }
            .search-form input[type="text"] { border-right: 2px solid var(--border-color); border-bottom: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="square" stroke-linejoin="miter"><path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                User IP Report (Last 30 Days)
            </h1>
            <div class="user-info">
                Welcome, <strong><?= htmlspecialchars($auth->getUsername()) ?></strong> | 
                <a href="index.php" class="flex-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg> Dashboard</a> | 
                <a href="failed_logins.php" class="flex-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg> Failed Logins</a> | 
                <a href="index.php?logout=1" class="flex-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg> Logout</a>
            </div>
        </header>

        <main>
            <section class="search-section">
                <h2><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg> Search for a User</h2>
                <form method="GET" action="<?= htmlspecialchars(BASE_PATH) ?>" class="search-form">
                    <input type="text" name="q" placeholder="Enter full or partial username (e.g., john)" value="<?= htmlspecialchars($searchQuery) ?>" required>
                    <button type="submit">Search</button>
                </form>

                <?php if ($searchQuery && empty($userOptions) && !$selectedUser): ?>
                    <div class="error-message">No users found matching "<strong><?= htmlspecialchars($searchQuery) ?></strong>".</div>
                <?php elseif ($searchQuery && !empty($userOptions) && !$selectedUser): ?>
                    <h3 style="color: var(--secondary-color); text-transform: uppercase; font-size: 0.9rem; margin-top: 2rem;">Select a user:</h3>
                    <ul class="user-options-list">
                        <?php foreach ($userOptions as $user): ?>
                            <li><a href="<?= htmlspecialchars(BASE_PATH) ?>?user=<?= urlencode($user) ?>"><?= htmlspecialchars($user) ?></a></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </section>

            <?php if ($selectedUser): ?>
            <section class="report-section region-changes">
                <h2><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z"></path></svg> IP Addresses for: <span class="highlight-upn"><?= htmlspecialchars($selectedUser) ?></span></h2>
                <div class="info-message">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
                    Showing activity for the last 30 days.
                </div>
                
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
                                        <td><strong><?= htmlspecialchars($row['ip_address']) ?></strong></td>
                                        <td><span style="font-weight: 700; color: var(--primary-color);"><?= htmlspecialchars($row['occurrence_count']) ?></span></td>
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
