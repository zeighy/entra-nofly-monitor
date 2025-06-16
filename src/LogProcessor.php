<?php
namespace App;

use PDO;
use DateTime;
use DateTimeZone;
use Microsoft\Graph\Generated\Models\SignIn;

class LogProcessor {
    private PDO $db;
    private GraphHelper $graphHelper;
    private Geolocation $geolocation;

    public function __construct() {
        $this->db = Database::getInstance();
        $this->graphHelper = new GraphHelper();
        $this->geolocation = new Geolocation();
    }

    public function run(): void {
        echo "Fetching logs from Microsoft Entra...\n";
        $signInLogs = $this->graphHelper->getSignInLogs();
        echo "Found " . count($signInLogs) . " logs to process.\n";

        $incidentsForEmail = [];

        $signInLogs = array_reverse($signInLogs);

        /** @var SignIn $log */
        foreach ($signInLogs as $log) {
            $ipAddress = $log->getIpAddress();
            if (empty($ipAddress) || str_starts_with($ipAddress, '127.')) {
                continue;
            }

            $logId = $log->getId();
            if ($this->logExists($logId)) {
                continue;
            }

            $userPrincipalName = $log->getUserPrincipalName();
            echo "Processing log for: " . $userPrincipalName . "\n";

            $geoInfo = $this->geolocation->getGeoInfo($ipAddress);
            
            $loginTime = $log->getCreatedDateTime();
            $loginTime->setTimezone(new DateTimeZone('UTC'));

            $status = $log->getStatus();
            $loginWasSuccessful = ($status !== null && $status->getErrorCode() === 0);
            $loginStatusMessage = $loginWasSuccessful ? 'Success' : ('Failure: ' . ($status ? $status->getFailureReason() : 'Unknown'));

            $currentLogData = [
                'entra_log_id' => $logId,
                'user_id' => $log->getUserId(),
                'user_principal_name' => $userPrincipalName,
                'ip_address' => $ipAddress,
                'login_time' => $loginTime->format('Y-m-d H:i:s'),
                'status' => $loginStatusMessage,
                'country' => $geoInfo['country'] ?? null,
                'city' => $geoInfo['city'] ?? null,
                'region' => $geoInfo['region'] ?? null, // Store region
                'lat' => $geoInfo['lat'] ?? null,
                'lon' => $geoInfo['lon'] ?? null,
                'is_impossible_travel' => false,
                'is_region_change' => false, // New field
                'travel_speed_kph' => null,
                'previous_log_id' => null
            ];
            
            $previousLogins = $this->getPreviousLoginsInLast24Hours($log->getUserId(), $currentLogData['login_time']);

            if (!empty($previousLogins)) {
                $maxSpeedKph = 0;
                $fastestPreviousLog = null;
                $regionChangeDetected = false;
                $regionChangePreviousLog = null;

                foreach ($previousLogins as $previousLog) {
                    // Check if the region is different and not null/empty
                    if (!$regionChangeDetected && !empty($previousLog['region']) && !empty($currentLogData['region']) && $previousLog['region'] !== $currentLogData['region']) {
                        $regionChangeDetected = true;
                        $regionChangePreviousLog = $previousLog;
                        $currentLogData['is_region_change'] = true;
                        // We link to the specific log that triggered the region change
                        $currentLogData['previous_log_id'] = $previousLog['id']; 
                        echo "REGION CHANGE DETECTED for " . $currentLogData['user_principal_name'] . "\n";
                        
                        // Add to email digest if the current login was successful
                        if ($loginWasSuccessful) {
                             $incidentsForEmail[] = [
                                'type' => 'region_change',
                                'current_log' => $currentLogData,
                                'previous_log' => $regionChangePreviousLog,
                            ];
                        }
                    }

                    // --- Impossible Travel Detection ---
                    if ($previousLog['ip_address'] !== $currentLogData['ip_address'] && $previousLog['lat'] && $currentLogData['lat']) {
                        $distance = $this->calculateDistance($previousLog['lat'], $previousLog['lon'], $currentLogData['lat'], $currentLogData['lon']);
                        $timeDiffSeconds = $loginTime->getTimestamp() - (new DateTime($previousLog['login_time']))->getTimestamp();
                        $timeDiffHours = $timeDiffSeconds > 0 ? $timeDiffSeconds / 3600 : 0;

                        if ($timeDiffHours > 0) {
                            $speedKph = $distance / $timeDiffHours;
                            if ($speedKph > $maxSpeedKph) {
                                $maxSpeedKph = $speedKph;
                                $fastestPreviousLog = $previousLog;
                            }
                        }
                    }
                }

                if ($maxSpeedKph > (float)$_ENV['IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD']) {
                    $currentLogData['is_impossible_travel'] = true;
                    $currentLogData['travel_speed_kph'] = $maxSpeedKph;
                    // Overwrite previous_log_id if impossible travel is more significant
                    $currentLogData['previous_log_id'] = $fastestPreviousLog['id']; 
                    
                    echo "IMPOSSIBLE TRAVEL DETECTED for " . $currentLogData['user_principal_name'] . " at " . round($maxSpeedKph) . " km/h\n";

                    $previousLoginWasSuccessful = ($fastestPreviousLog['status'] === 'Success');
                    if ($loginWasSuccessful && $previousLoginWasSuccessful) {
                        $incidentsForEmail[] = [
                            'type' => 'impossible_travel',
                            'current_log' => $currentLogData,
                            'previous_log' => $fastestPreviousLog,
                            'speed' => $maxSpeedKph,
                        ];
                    }
                }
            }

            $this->saveLoginLog($currentLogData);
        }
        
        if (!empty($incidentsForEmail)) {
            echo "Sending consolidated email for " . count($incidentsForEmail) . " incidents.\n";
            Mailer::sendConsolidatedAlert($incidentsForEmail);
        }

        echo "Log processing complete.\n";
        $this->pruneOldLogs();
    }

    private function logExists(string $entraLogId): bool {
        $stmt = $this->db->prepare("SELECT 1 FROM login_logs WHERE entra_log_id = :id");
        $stmt->execute(['id' => $entraLogId]);
        return $stmt->fetchColumn() !== false;
    }
    
    private function getPreviousLoginsInLast24Hours(string $userId, string $currentLoginTime): array {
        $stmt = $this->db->prepare(
            "SELECT * FROM login_logs 
             WHERE user_id = :userId 
             AND login_time < :currentLoginTime
             AND login_time >= :time24HoursAgo
             ORDER BY login_time DESC"
        );
        $twentyFourHoursAgo = (new DateTime($currentLoginTime))->modify('-24 hours')->format('Y-m-d H:i:s');
        $stmt->execute(['userId' => $userId, 'currentLoginTime' => $currentLoginTime, 'time24HoursAgo' => $twentyFourHoursAgo]);
        return $stmt->fetchAll() ?: [];
    }
    
    private function saveLoginLog(array $data): void {
        $data['is_impossible_travel'] = (int)($data['is_impossible_travel'] ?? false);
        $data['is_region_change'] = (int)($data['is_region_change'] ?? false);
        
        $sql = "INSERT INTO login_logs (entra_log_id, user_id, user_principal_name, ip_address, login_time, status, country, region, city, lat, lon, is_impossible_travel, is_region_change, travel_speed_kph, previous_log_id)
                VALUES (:entra_log_id, :user_id, :user_principal_name, :ip_address, :login_time, :status, :country, :region, :city, :lat, :lon, :is_impossible_travel, :is_region_change, :travel_speed_kph, :previous_log_id)";
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute($data);
    }
    
    private function calculateDistance(float $lat1, float $lon1, float $lat2, float $lon2): float {
        $earthRadiusKm = 6371;
        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);
        $a = sin($dLat / 2) * sin($dLat / 2) + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon / 2) * sin($dLon / 2);
        $c = 2 * atan2(sqrt($a), sqrt(1 - $a));
        return $earthRadiusKm * $c;
    }

    private function pruneOldLogs(): void {
        echo "Pruning logs older than 180 days...\n";
        $stmt = $this->db->prepare("DELETE FROM login_logs WHERE login_time < NOW() - INTERVAL 180 DAY");
        $deletedRows = $stmt->execute() ? $stmt->rowCount() : 0;
        echo "Pruned $deletedRows old log entries.\n";
    }
}
