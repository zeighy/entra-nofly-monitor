<?php
require_once __DIR__ . '/../../vendor/autoload.php';

// Load credentials from secrets.php
$secretsFile = __DIR__ . '/../../secrets.php';
if (!file_exists($secretsFile)) {
    http_response_code(500);
    echo json_encode(['error' => 'Server configuration missing.']);
    exit;
}
$secrets = require $secretsFile;
foreach ($secrets as $key => $value) {
    $_ENV[$key] = $value;
}

header('Content-Type: application/json');

// Get API Token from environment
$apiToken = $_ENV['API_TOKEN'] ?? '';
if (empty($apiToken)) {
    http_response_code(403);
    echo json_encode(['error' => 'API access is disabled.']);
    exit;
}

// Check Authorization header
$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';

if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches) || !hash_equals($apiToken, $matches[1])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

use App\Database;

try {
    $db = Database::getInstance();

    $alerts = [];

    // 1. Impossible Travel Alerts
    $sqlTravel = "
        SELECT l.user_principal_name, l.login_time, l.ip_address, l.city, l.country, l.travel_speed_kph, e.sent_at as email_sent_at
        FROM login_logs l
        JOIN email_alerts e ON l.id = e.alert_log_id AND l.previous_log_id = e.compared_log_id
        WHERE l.is_impossible_travel = 1
        AND e.alert_type = 'impossible_travel'
        AND e.sent_at >= NOW() - INTERVAL 1 DAY
        ORDER BY l.login_time DESC
    ";
    $stmtTravel = $db->query($sqlTravel);
    while ($row = $stmtTravel->fetch(\PDO::FETCH_ASSOC)) {
        $row['alert_type'] = 'impossible_travel';
        $alerts[] = $row;
    }

    // 2. Region Change Alerts
    $sqlRegion = "
        SELECT l.user_principal_name, l.login_time, l.ip_address, l.city, l.region, l.country, e.sent_at as email_sent_at
        FROM login_logs l
        JOIN email_alerts e ON l.id = e.alert_log_id AND l.previous_log_id = e.compared_log_id
        WHERE l.is_region_change = 1
        AND e.alert_type = 'region_change'
        AND e.sent_at >= NOW() - INTERVAL 1 DAY
        ORDER BY l.login_time DESC
    ";
    $stmtRegion = $db->query($sqlRegion);
    while ($row = $stmtRegion->fetch(\PDO::FETCH_ASSOC)) {
        $row['alert_type'] = 'region_change';
        $alerts[] = $row;
    }

    // 3. Device Change Alerts
    // Device changes always send an email according to documentation
    $sqlDevice = "
        SELECT user_principal_name, change_time as event_time, device_display_name, change_type
        FROM auth_device_changes
        WHERE change_time >= NOW() - INTERVAL 1 DAY
        ORDER BY change_time DESC
    ";
    $stmtDevice = $db->query($sqlDevice);
    while ($row = $stmtDevice->fetch(\PDO::FETCH_ASSOC)) {
        $row['alert_type'] = 'device_change';
        $row['email_sent_at'] = $row['event_time']; // Since it's sent concurrently
        $alerts[] = $row;
    }

    // 4. Failed Login Counts (Last 24 hours)
    $failedLogins = [];
    $sqlFailed = "
        SELECT user_principal_name, COUNT(*) as failed_count
        FROM login_logs
        WHERE login_time >= NOW() - INTERVAL 1 DAY
        AND status LIKE 'Failure%'
        GROUP BY user_principal_name
        ORDER BY failed_count DESC
    ";
    $stmtFailed = $db->query($sqlFailed);
    while ($row = $stmtFailed->fetch(\PDO::FETCH_ASSOC)) {
        $failedLogins[] = [
            'user_principal_name' => $row['user_principal_name'],
            'failed_count' => (int)$row['failed_count']
        ];
    }

    $response = [
        'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
        'alerts' => $alerts,
        'failed_logins' => $failedLogins
    ];

    echo json_encode($response, JSON_PRETTY_PRINT);

} catch (\Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error.']);
}
