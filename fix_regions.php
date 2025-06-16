<?php
// This is a one-time helper script to find IP addresses with two-character
// region codes in the login_logs table and update them to the full region name.
// It also prunes old entries from the ip_geolocation_cache table.
// Feel free to run on a daily cron to prune cached IPs.

echo "--- Starting Region Name Fixer & Cache Pruner Script ---\n\n";

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
    putenv("$key=$value");
}

use App\Database;

try {
    $db = Database::getInstance();
    echo "Database connection successful.\n";

    // --- Fix Region Names from two letter to full name ---
    echo "\n--- Checking for short region names to fix... ---\n";
    $stmt = $db->prepare(
        "SELECT DISTINCT ip_address, region FROM login_logs WHERE LENGTH(region) <= 3 AND region IS NOT NULL AND region != ''"
    );
    $stmt->execute();
    $ipsToFix = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (empty($ipsToFix)) {
        echo "No IP addresses with short region codes found in the login_logs table. Nothing to fix.\n";
    } else {
        echo "Found " . count($ipsToFix) . " distinct IP addresses to check and fix.\n\n";
        $apiUrlBase = $_ENV['IP_GEOLOCATION_API_URL'];
        $totalUpdatedLogs = 0;

        foreach ($ipsToFix as $ipData) {
            $ipAddress = $ipData['ip_address'];
            $oldRegion = $ipData['region'];

            echo "Processing IP: $ipAddress (Current short region: '$oldRegion')\n";

            $url = $apiUrlBase . $ipAddress;
            $responseJson = @file_get_contents($url);
            
            if ($responseJson === false) {
                echo "  [ERROR] Failed to fetch data for $ipAddress from API.\n";
                continue;
            }

            $data = json_decode($responseJson, true);

            if ($data && $data['status'] === 'success' && !empty($data['regionName'])) {
                $newRegionName = $data['regionName'];
                
                if ($newRegionName !== $oldRegion) {
                    $updateCacheStmt = $db->prepare(
                        "INSERT INTO ip_geolocation_cache (ip_address, region) VALUES (:ip, :new_region_insert)
                         ON DUPLICATE KEY UPDATE region = :new_region_update"
                    );
                    $updateCacheStmt->execute([
                        'ip' => $ipAddress,
                        'new_region_insert' => $newRegionName,
                        'new_region_update' => $newRegionName
                    ]);
                    echo "  [SUCCESS] Updated cache: '$oldRegion' -> '$newRegionName'\n";

                    $updateLogsStmt = $db->prepare("UPDATE login_logs SET region = :new_region WHERE ip_address = :ip");
                    $updateLogsStmt->execute(['new_region' => $newRegionName, 'ip' => $ipAddress]);
                    $affectedRows = $updateLogsStmt->rowCount();
                    $totalUpdatedLogs += $affectedRows;
                    echo "  [SUCCESS] Updated $affectedRows entries in the login_logs table.\n";

                } else {
                    echo "  [INFO] Full region name is the same as the cached one. No update needed.\n";
                }
            } else {
                echo "  [ERROR] Received invalid or failed response from API for $ipAddress.\n";
            }
            sleep(1); 
        }
        echo "\nRegion fix complete. Total entries updated in login_logs: $totalUpdatedLogs\n";
    }

    // --- Prune Old Cached IP Info ---
    echo "\n--- Pruning cached IP info older than 90 days... ---\n";
    $pruneStmt = $db->prepare(
        "DELETE FROM ip_geolocation_cache WHERE last_updated < NOW() - INTERVAL 90 DAY"
    );
    $pruneStmt->execute();
    $prunedRows = $pruneStmt->rowCount();
    echo "Pruned $prunedRows old entries from the IP geolocation cache.\n";


    echo "\n--- Script Finished ---\n";


} catch (\Exception $e) {
    die("An application error occurred: " . $e->getMessage() . "\n");
}
