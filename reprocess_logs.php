<?php
echo "--- Starting Historical Log Reprocessing Script ---\n\n";

// Bootstrap the application environment
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
    if (!is_array($value)) {
        putenv("$key=$value");
    }
}

use App\Database;
use App\Mailer;

function isIpWhitelisted(string $ipAddress, array $whitelist): bool {
    return in_array($ipAddress, $whitelist);
}

try {
    $db = Database::getInstance();
    echo "Database connection successful.\n";
    
    // Load the IP whitelist into memory
    $whitelistStmt = $db->query("SELECT ip_address FROM ip_whitelist");
    $ipWhitelist = $whitelistStmt->fetchAll(PDO::FETCH_COLUMN, 0);
    echo "Loaded " . count($ipWhitelist) . " IP addresses from whitelist.\n";

    echo "Resetting all existing alert flags in the database...\n";
    $db->query("UPDATE login_logs SET is_impossible_travel = 0, is_region_change = 0, travel_speed_kph = NULL, previous_log_id = NULL");
    $db->query("TRUNCATE TABLE email_alerts");

    $allLogsStmt = $db->prepare("SELECT * FROM login_logs ORDER BY user_id, login_time ASC");
    $allLogsStmt->execute();
    $allLogs = $allLogsStmt->fetchAll(PDO::FETCH_ASSOC);

    if (empty($allLogs)) {
        echo "No logs found in the database to reprocess. Exiting.\n";
        exit;
    }

    echo "Found " . count($allLogs) . " total logs to re-process.\n\n";

    $totalUpdated = 0;
    $incidentsForEmail = [];
    $userHistories = [];

    foreach ($allLogs as $currentLog) {
        $userId = $currentLog['user_id'];
        
        echo "Processing Log ID #" . $currentLog['id'] . " for user " . $currentLog['user_principal_name'] . "...\n";

        $maxSpeedKph = 0;
        $fastestPreviousLog = null;
        $isRegionChangeForUi = false;
        $shouldEmailForRegionChange = false;
        $regionChangePreviousLogForUi = null;
        $loginWasSuccessful = ($currentLog['status'] === 'Success');

        if (isset($userHistories[$userId])) {
            $twentyFourHoursAgo = (new DateTime($currentLog['login_time']))->modify('-24 hours')->getTimestamp();

            foreach ($userHistories[$userId] as $previousLog) {
                if ((new DateTime($previousLog['login_time']))->getTimestamp() < $twentyFourHoursAgo) continue;

                if (!$isRegionChangeForUi && $previousLog['ip_address'] !== $currentLog['ip_address'] && !empty($previousLog['region']) && !empty($currentLog['region']) && $previousLog['region'] !== $currentLog['region'] && $loginWasSuccessful && $previousLog['status'] === 'Success') {
                    $isRegionChangeForUi = true;
                    $regionChangePreviousLogForUi = $previousLog;
                    $distance = calculateDistance($previousLog['lat'], $previousLog['lon'], $currentLog['lat'], $currentLog['lon']);
                    if ($distance > (float)$_ENV['REGION_CHANGE_IGNORE_KM']) {
                        $shouldEmailForRegionChange = true;
                    }
                }

                if ($previousLog['ip_address'] !== $currentLog['ip_address'] && !empty($previousLog['lat']) && !empty($currentLog['lat'])) {
                    $distance = calculateDistance($previousLog['lat'], $previousLog['lon'], $currentLog['lat'], $currentLog['lon']);
                    $timeDiffHours = ((new DateTime($currentLog['login_time']))->getTimestamp() - (new DateTime($previousLog['login_time']))->getTimestamp()) / 3600;
                    if ($timeDiffHours > 0) {
                        $speedKph = $distance / $timeDiffHours;
                        if ($speedKph > $maxSpeedKph) {
                            $maxSpeedKph = $speedKph;
                            $fastestPreviousLog = $previousLog;
                        }
                    }
                }
            }
        }
        
        $userHistories[$userId][] = $currentLog;

        $isImpossibleTravel = ($maxSpeedKph > (float)$_ENV['IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD']);
        $previousLogId = null;
        
        if ($isImpossibleTravel) {
            $previousLogId = $fastestPreviousLog['id'];
        } elseif ($isRegionChangeForUi) {
            $previousLogId = $regionChangePreviousLogForUi['id'];
        }
        
        if ($isImpossibleTravel || $isRegionChangeForUi) {
            echo "  [ALERT] Anomaly found for Log ID #" . $currentLog['id'] . ". Updating record.\n";
            $updateStmt = $db->prepare("UPDATE login_logs SET is_impossible_travel = :is_impossible_travel, is_region_change = :is_region_change, travel_speed_kph = :travel_speed_kph, previous_log_id = :previous_log_id WHERE id = :id");
            $updateStmt->execute(['is_impossible_travel' => (int)$isImpossibleTravel, 'is_region_change' => (int)$isRegionChangeForUi, 'travel_speed_kph' => $isImpossibleTravel ? $maxSpeedKph : null, 'previous_log_id' => $previousLogId, 'id' => $currentLog['id']]);
            $totalUpdated++;
        }

        if ($isImpossibleTravel) {
            $previousLoginWasSuccessful = ($fastestPreviousLog['status'] === 'Success');
            if ($loginWasSuccessful && $previousLoginWasSuccessful && !isIpWhitelisted($currentLog['ip_address'], $ipWhitelist)) {
                $incidentsForEmail[] = ['type' => 'impossible_travel', 'current_log' => array_merge($currentLog, ['travel_speed_kph' => $maxSpeedKph]), 'previous_log' => $fastestPreviousLog, 'speed' => $maxSpeedKph];
            }
        }
        if ($shouldEmailForRegionChange && !isIpWhitelisted($currentLog['ip_address'], $ipWhitelist)) {
             $incidentsForEmail[] = ['type' => 'region_change', 'current_log' => $currentLog, 'previous_log' => $regionChangePreviousLogForUi];
        }
    }

    if (!empty($incidentsForEmail)) {
        echo "\n--- Sending consolidated email for " . count($incidentsForEmail) . " re-processed incidents. ---\n";
        Mailer::sendConsolidatedAlert($incidentsForEmail, $db);
    } else {
        echo "\n--- No new incidents found that qualify for an email alert. ---\n";
    }

    echo "\n--- Reprocessing Complete ---\n";
    echo "Total log entries updated: $totalUpdated\n";

} catch (\Exception $e) {
    die("An application error occurred: " . $e->getMessage() . "\n");
}

function calculateDistance(?float $lat1, ?float $lon1, ?float $lat2, ?float $lon2): float {
    if ($lat1 === null || $lon1 === null || $lat2 === null || $lon2 === null) return 0;
    $earthRadiusKm = 6371;
    $dLat = deg2rad($lat2 - $lat1);
    $dLon = deg2rad($lon2 - $lon1);
    $a = sin($dLat / 2) * sin($dLat / 2) + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon / 2) * sin($dLon / 2);
    $c = 2 * atan2(sqrt($a), sqrt(1 - $a));
    return $earthRadiusKm * $c;
}
