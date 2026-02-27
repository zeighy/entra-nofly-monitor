<?php

require_once __DIR__ . '/vendor/autoload.php';

// Load credentials from secrets.php
$secretsFile = __DIR__ . '/secrets.php';
if (!file_exists($secretsFile)) {
    die("FATAL ERROR: secrets.php file not found. Please create it in the project root.\n");
}
$secrets = require $secretsFile;

// Populate $_ENV, but only putenv for non-arrays to avoid warnings
foreach ($secrets as $key => $value) {
    $_ENV[$key] = $value;
    if (!is_array($value)) {
        putenv("$key=$value");
    }
}

use App\Database;
use App\Mailer;

$db = Database::getInstance();
$mailer = new Mailer();

echo "Starting weekly digest generation...\n";

// Fetch all distinct users seen in the last 7 days (either from detections or successful logins)
$stmt = $db->query("SELECT DISTINCT user_principal_name FROM login_logs WHERE login_time >= NOW() - INTERVAL 7 DAY AND (status = 'Success' OR is_impossible_travel = 1 OR is_region_change = 1)");
$logUsers = $stmt->fetchAll(PDO::FETCH_COLUMN);

$stmt = $db->query("SELECT DISTINCT user_principal_name FROM auth_device_changes WHERE change_time >= NOW() - INTERVAL 7 DAY");
$deviceUsers = $stmt->fetchAll(PDO::FETCH_COLUMN);

// Merge and deduplicate the user lists to avoid collation mix errors from SQL UNION
$users = array_values(array_unique(array_merge($logUsers, $deviceUsers)));

if (empty($users)) {
    echo "No relevant user activity found in the last 7 days. Exiting.\n";
    exit(0);
}

$digestData = [];

foreach ($users as $upn) {
    $userData = [
        'upn' => $upn,
        'impossible_travel_count' => 0,
        'region_change_count' => 0,
        'device_change_count' => 0,
        'current_regions' => [], // Region => Count (Last 7 days)
        'prior_regions' => []    // Regions (Days 8-14 ago)
    ];

    // Count Impossible Travel (Last 7 days)
    $stmt = $db->prepare("SELECT COUNT(*) FROM login_logs WHERE user_principal_name = ? AND login_time >= NOW() - INTERVAL 7 DAY AND is_impossible_travel = 1");
    $stmt->execute([$upn]);
    $userData['impossible_travel_count'] = $stmt->fetchColumn();

    // Count Region Change (Last 7 days)
    $stmt = $db->prepare("SELECT COUNT(*) FROM login_logs WHERE user_principal_name = ? AND login_time >= NOW() - INTERVAL 7 DAY AND is_region_change = 1");
    $stmt->execute([$upn]);
    $userData['region_change_count'] = $stmt->fetchColumn();

    // Count Device Changes (Last 7 days)
    $stmt = $db->prepare("SELECT COUNT(*) FROM auth_device_changes WHERE user_principal_name = ? AND change_time >= NOW() - INTERVAL 7 DAY");
    $stmt->execute([$upn]);
    $userData['device_change_count'] = $stmt->fetchColumn();

    // Get successful login regions and counts (Last 7 days)
    $stmt = $db->prepare("
        SELECT CONCAT(region, ', ', country) AS location, COUNT(*) as count 
        FROM login_logs 
        WHERE user_principal_name = ? AND login_time >= NOW() - INTERVAL 7 DAY AND status = 'Success'
        GROUP BY location
    ");
    $stmt->execute([$upn]);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        if ($row['location'] != ', ') {
             $userData['current_regions'][$row['location']] = $row['count'];
        }
    }

    // Get successful login regions (Prior 7 days: 8 to 14 days ago)
    $stmt = $db->prepare("
        SELECT DISTINCT CONCAT(region, ', ', country) AS location
        FROM login_logs 
        WHERE user_principal_name = ? 
        AND login_time >= NOW() - INTERVAL 14 DAY 
        AND login_time < NOW() - INTERVAL 7 DAY 
        AND status = 'Success'
    ");
    $stmt->execute([$upn]);
    $userData['prior_regions'] = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $userData['prior_regions'] = array_filter($userData['prior_regions'], function($val) { return $val != ', '; });

    // Only add to digest if there's *any* activity (detections or successful logins)
    if ($userData['impossible_travel_count'] > 0 || 
        $userData['region_change_count'] > 0 || 
        $userData['device_change_count'] > 0 || 
        !empty($userData['current_regions'])) {
        
        $digestData[] = $userData;
    }
}

if (empty($digestData)) {
     echo "No data to report in digest. Exiting.\n";
     exit(0);
}

// Build Email HTML
$htmlBody = "<h2>Weekly Entra User Activity Digest</h2>";
$htmlBody .= "<p>Consolidated overview of detections and successful logins per user for the last 7 days.</p>";

$htmlBody .= "<table border='1' cellpadding='8' style='border-collapse: collapse; width: 100%; font-family: sans-serif;'>";
$htmlBody .= "<tr style='background-color: #f2f2f2;'>";
$htmlBody .= "<th>User</th>";
$htmlBody .= "<th>Detections (Last 7 Days)</th>";
$htmlBody .= "<th>Successful Logins (Last 7 Days)</th>";
$htmlBody .= "<th>Prior Successful Logins (Days 8-14 Ago)</th>";
$htmlBody .= "</tr>";

foreach ($digestData as $user) {
    $htmlBody .= "<tr>";
    
    // User
    $htmlBody .= "<td><strong>" . htmlspecialchars($user['upn']) . "</strong></td>";
    
    // Detections
    $htmlBody .= "<td>";
    $htmlBody .= "Impossible Travel: " . $user['impossible_travel_count'] . "<br>";
    $htmlBody .= "Region Changes: " . $user['region_change_count'] . "<br>";
    $htmlBody .= "Device Changes: " . $user['device_change_count'] . "<br>";
    $htmlBody .= "</td>";
    
    // Current Regions
    $htmlBody .= "<td>";
    if (empty($user['current_regions'])) {
        $htmlBody .= "<em>None detected</em>";
    } else {
        $htmlBody .= "<ul style='margin: 0; padding-left: 20px;'>";
        foreach ($user['current_regions'] as $region => $count) {
            $htmlBody .= "<li>" . htmlspecialchars($region) . " (" . $count . " logins)</li>";
        }
        $htmlBody .= "</ul>";
    }
    $htmlBody .= "</td>";

    // Prior Regions
    $htmlBody .= "<td>";
    if (empty($user['prior_regions'])) {
        $htmlBody .= "<em>None detected</em>";
    } else {
        $htmlBody .= "<ul style='margin: 0; padding-left: 20px;'>";
        foreach ($user['prior_regions'] as $region) {
            $htmlBody .= "<li>" . htmlspecialchars($region) . "</li>";
        }
        $htmlBody .= "</ul>";
    }
    $htmlBody .= "</td>";

    $htmlBody .= "</tr>";
}

$htmlBody .= "</table>";
$htmlBody .= "<br><p><small>This is an automated message from your Entra Monitor instance.</small></p>";

// Send Email
$subject = "Weekly Entra Activity Digest - " . date('Y-m-d');
$recipient = $_ENV['ADMIN_ALERT_EMAIL'] ?? '';
$ccRecipients = isset($_ENV['MAILER_CC_RECIPIENTS']) ? explode(',', $_ENV['MAILER_CC_RECIPIENTS']) : [];

if (empty($recipient)) {
     echo "Error: ADMIN_ALERT_EMAIL is not configured in secrets.php.\n";
     exit(1);
}

try {
    $mailer->sendHtmlEmail($recipient, $subject, $htmlBody, $ccRecipients);
    echo "Successfully sent weekly digest to $recipient.\n";
} catch (Exception $e) {
    echo "Failed to send weekly digest: " . $e->getMessage() . "\n";
}

