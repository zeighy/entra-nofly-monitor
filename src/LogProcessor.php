<?php
namespace App;

use PDO;
use DateTime;
use DateTimeZone;
use Microsoft\Graph\Generated\Models\SignIn;
use Microsoft\Graph\Generated\Models\Fido2AuthenticationMethod;
use Microsoft\Graph\Generated\Models\MicrosoftAuthenticatorAuthenticationMethod;
use Microsoft\Graph\Generated\Models\SoftwareOathAuthenticationMethod;

class LogProcessor {
    private PDO $db;
    private GraphHelper $graphHelper;
    private Geolocation $geolocation;
    private array $ipWhitelist = [];
    private array $usersProcessedForDeviceCheck = []; // Prevents checking the same user multiple times per run

    public function __construct() {
        $this->db = Database::getInstance();
        $this->graphHelper = new GraphHelper();
        $this->geolocation = new Geolocation();
        $this->loadIpWhitelist();
    }
    
    private function loadIpWhitelist(): void {
        $stmt = $this->db->query("SELECT ip_address FROM ip_whitelist");
        $this->ipWhitelist = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    }

    private function isIpWhitelisted(string $ipAddress): bool {
        return in_array($ipAddress, $this->ipWhitelist);
    }

    public function run(): void {
        echo "Fetching logs from Microsoft Entra...\n";
        $signInLogs = $this->graphHelper->getSignInLogs();
        echo "Found " . count($signInLogs) . " logs to process.\n";

        $incidentsForEmail = [];
        $this->usersProcessedForDeviceCheck = []; // Reset for each run

        $signInLogs = array_reverse($signInLogs);

        foreach ($signInLogs as $log) {
            $ipAddress = $log->getIpAddress();
            if (empty($ipAddress) || str_starts_with($ipAddress, '127.')) continue;
            if ($this->logExists($log->getId())) continue;

            $userPrincipalName = $log->getUserPrincipalName();
            $userId = $log->getUserId();
            echo "Processing log for: " . $userPrincipalName . "\n";

            if (!in_array($userId, $this->usersProcessedForDeviceCheck)) {
                echo "  Checking auth devices for user: $userId\n";
                $deviceChanges = $this->checkForDeviceChanges($userId, $userPrincipalName);
                if (!empty($deviceChanges)) {
                    $incidentsForEmail = array_merge($incidentsForEmail, $deviceChanges);
                }
                $this->usersProcessedForDeviceCheck[] = $userId;
            }

            $geoInfo = $this->geolocation->getGeoInfo($ipAddress);
            $loginTime = $log->getCreatedDateTime();
            $loginTime->setTimezone(new DateTimeZone('UTC'));
            $status = $log->getStatus();
            $loginWasSuccessful = ($status !== null && $status->getErrorCode() === 0);
            $loginStatusMessage = $loginWasSuccessful ? 'Success' : ('Failure: ' . ($status ? $status->getFailureReason() : 'Unknown'));

            $currentLogData = [
                'entra_log_id' => $log->getId(), 'user_id' => $userId, 'user_principal_name' => $userPrincipalName,
                'ip_address' => $ipAddress, 'login_time' => $loginTime->format('Y-m-d H:i:s'), 'status' => $loginStatusMessage,
                'country' => $geoInfo['country'] ?? null, 'region' => $geoInfo['regionName'] ?? $geoInfo['region'] ?? null,
                'city' => $geoInfo['city'] ?? null, 'lat' => $geoInfo['lat'] ?? null, 'lon' => $geoInfo['lon'] ?? null,
                'is_impossible_travel' => false, 'is_region_change' => false, 'travel_speed_kph' => null, 'previous_log_id' => null
            ];
            
            $previousLogins = $this->getPreviousLoginsInLast24Hours($userId, $currentLogData['login_time']);

            $isImpossibleTravel = false;
            $isRegionChangeForUi = false;
            $shouldEmailForRegionChange = false;
            $fastestPreviousLog = null;
            $regionChangePreviousLogForUi = null;
            
            if (!empty($previousLogins)) {
                $maxSpeedKph = 0;

                foreach ($previousLogins as $previousLog) {
                    if (!$isRegionChangeForUi && $previousLog['ip_address'] !== $currentLogData['ip_address'] && !empty($previousLog['region']) && !empty($currentLogData['region']) && $previousLog['region'] !== $currentLogData['region'] && $loginWasSuccessful && $previousLog['status'] === 'Success') {
                        $isRegionChangeForUi = true;
                        $regionChangePreviousLogForUi = $previousLog;
                        $distance = $this->calculateDistance($previousLog['lat'], $previousLog['lon'], $currentLogData['lat'], $currentLogData['lon']);
                        if ($distance > (float)$_ENV['REGION_CHANGE_IGNORE_KM']) {
                            $shouldEmailForRegionChange = true;
                        }
                    }

                    if ($previousLog['ip_address'] !== $currentLogData['ip_address'] && !empty($previousLog['lat']) && !empty($currentLogData['lat'])) {
                        $distance = $this->calculateDistance($previousLog['lat'], $previousLog['lon'], $currentLogData['lat'], $currentLogData['lon']);
                        $timeDiffHours = ((new DateTime($currentLogData['login_time']))->getTimestamp() - (new DateTime($previousLog['login_time']))->getTimestamp()) / 3600;
                        if ($timeDiffHours > 0) {
                            $speedKph = $distance / $timeDiffHours;
                            if ($speedKph > $maxSpeedKph) {
                                $maxSpeedKph = $speedKph;
                                $fastestPreviousLog = $previousLog;
                            }
                        }
                    }
                }
                $isImpossibleTravel = ($maxSpeedKph > (float)$_ENV['IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD']);
                
                $currentLogData['is_impossible_travel'] = $isImpossibleTravel;
                $currentLogData['is_region_change'] = $isRegionChangeForUi;
                if ($isImpossibleTravel) {
                    $currentLogData['travel_speed_kph'] = $maxSpeedKph;
                    $currentLogData['previous_log_id'] = $fastestPreviousLog['id']; 
                } elseif ($isRegionChangeForUi) {
                    $currentLogData['previous_log_id'] = $regionChangePreviousLogForUi['id']; 
                }
            }

            $newLogId = $this->saveLoginLog($currentLogData);
            $currentLogData['id'] = $newLogId; 

            if ($isImpossibleTravel) {
                $previousLoginWasSuccessful = ($fastestPreviousLog['status'] === 'Success');
                $isWhitelisted = $this->isIpWhitelisted($currentLogData['ip_address']) || $this->isIpWhitelisted($fastestPreviousLog['ip_address']);
                if ($loginWasSuccessful && $previousLoginWasSuccessful && !$isWhitelisted) {
                    $incident = ['type' => 'impossible_travel', 'current_log' => $currentLogData, 'previous_log' => $fastestPreviousLog, 'speed' => $maxSpeedKph];
                    $incidentsForEmail[] = $incident;
                    Mailer::sendUserAlert($userPrincipalName, 'impossible_travel', $incident, $this->db);
                }
                echo "IMPOSSIBLE TRAVEL DETECTED for " . $currentLogData['user_principal_name'] . "\n";
            }
            if ($shouldEmailForRegionChange) {
                $isWhitelisted = $this->isIpWhitelisted($currentLogData['ip_address']) || $this->isIpWhitelisted($regionChangePreviousLogForUi['ip_address']);
                if (!$isWhitelisted) {
                     $incident = ['type' => 'region_change', 'current_log' => $currentLogData, 'previous_log' => $regionChangePreviousLogForUi];
                     $incidentsForEmail[] = $incident;
                     Mailer::sendUserAlert($userPrincipalName, 'region_change', $incident, $this->db);
                }
            }
            if ($isRegionChangeForUi) {
                echo "REGION CHANGE DETECTED for " . $currentLogData['user_principal_name'] . "\n";
            }

            if (!$loginWasSuccessful && str_contains($loginStatusMessage, 'The account is locked')) {
                $isWhitelisted = $this->isIpWhitelisted($currentLogData['ip_address']);
                if (!$isWhitelisted) {
                    $incident = ['type' => 'account_locked', 'current_log' => $currentLogData];
                    Mailer::sendUserAlert($userPrincipalName, 'account_locked', $incident, $this->db);
                    echo "ACCOUNT LOCKED DETECTED for " . $currentLogData['user_principal_name'] . "\n";
                }
            }
        }
        
        if (!empty($incidentsForEmail)) {
            echo "Sending consolidated email for " . count($incidentsForEmail) . " incidents.\n";
            Mailer::sendConsolidatedAlert($incidentsForEmail, $this->db);
        }

        echo "Log processing complete.\n";
        $this->pruneOldLogs();
    }

    private function checkForDeviceChanges(string $userId, string $userPrincipalName): array {
        $newIncidents = [];
        $currentMethodsRaw = $this->graphHelper->getAuthMethodsForUser($userId);
        $knownMethods = $this->getKnownDevicesForUser($userId);

        $currentMethods = [];
        foreach ($currentMethodsRaw as $method) {
            $displayName = null; // Flag for valid MFA types
            $type = null;
            $deviceId = $method->getId();

            if ($method instanceof MicrosoftAuthenticatorAuthenticationMethod) {
                $displayName = $method->getDevice() ? ($method->getDevice()->getDisplayName() ?? 'Authenticator App') : 'Authenticator App (No Device Name)';
                $type = 'Microsoft Authenticator';
            } elseif ($method instanceof Fido2AuthenticationMethod) {
                $displayName = $method->getDisplayName() ?? 'Security Key';
                $type = 'FIDO2 Security Key';
            } elseif ($method instanceof SoftwareOathAuthenticationMethod) {
                $displayName = 'Third-Party Authenticator';
                $type = 'Software OATH Token';
            }
            
            if ($displayName !== null) {
                 $currentMethods[$deviceId] = ['displayName' => $displayName, 'type' => $type];
            }
        }

        $currentIds = array_keys($currentMethods);
        $knownIds = array_keys($knownMethods);

        $addedIds = array_diff($currentIds, $knownIds);
        $removedIds = array_diff($knownIds, $currentIds);

        foreach ($addedIds as $id) {
            $device = $currentMethods[$id];
            $logId = $this->logDeviceChange($userId, $userPrincipalName, $device['displayName'], 'Added');
            $incident = ['type' => 'auth_device_change', 'change' => 'Added', 'user' => $userPrincipalName, 'device' => $device['displayName'], 'log_id' => $logId];
            $newIncidents[] = $incident;
            Mailer::sendUserAlert($userPrincipalName, 'auth_device_change', $incident, $this->db);
            echo "  [ALERT] New MFA device added for $userPrincipalName: " . $device['displayName'] . "\n";
        }

        foreach ($removedIds as $id) {
            $device = $knownMethods[$id];
            $logId = $this->logDeviceChange($userId, $userPrincipalName, $device['displayName'], 'Removed');
            $incident = ['type' => 'auth_device_change', 'change' => 'Removed', 'user' => $userPrincipalName, 'device' => $device['displayName'], 'log_id' => $logId];
            $newIncidents[] = $incident;
            Mailer::sendUserAlert($userPrincipalName, 'auth_device_change', $incident, $this->db);
            echo "  [ALERT] MFA device removed for $userPrincipalName: " . $device['displayName'] . "\n";
        }

        if (!empty($addedIds) || !empty($removedIds)) {
            $this->updateKnownDevicesForUser($userId, $currentMethodsRaw);
        }
        
        return $newIncidents;
    }

    private function getKnownDevicesForUser(string $userId): array {
        $stmt = $this->db->prepare("SELECT device_id, display_name, device_type FROM user_auth_devices WHERE user_id = ?");
        $stmt->execute([$userId]);
        $results = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        $devices = [];
        foreach ($results as $row) {
            if (is_array($row) && isset($row['device_id'], $row['display_name'], $row['device_type'])) {
                $devices[$row['device_id']] = [
                    'displayName' => $row['display_name'],
                    'type' => $row['device_type']
                ];
            }
        }
        return $devices;
    }

    private function logDeviceChange(string $userId, string $userPrincipalName, string $displayName, string $changeType): int {
        $stmt = $this->db->prepare("INSERT INTO auth_device_changes (user_id, user_principal_name, device_display_name, change_type) VALUES (?, ?, ?, ?)");
        $stmt->execute([$userId, $userPrincipalName, $displayName, $changeType]);
        return (int)$this->db->lastInsertId();
    }
    
    private function updateKnownDevicesForUser(string $userId, array $methods): void {
        $this->db->prepare("DELETE FROM user_auth_devices WHERE user_id = ?")->execute([$userId]);
        $stmt = $this->db->prepare("INSERT IGNORE INTO user_auth_devices (user_id, device_id, display_name, device_type) VALUES (?, ?, ?, ?)");
        
        foreach ($methods as $method) {
            $displayName = null; // Flag for valid MFA types
            $type = null;
            $deviceId = $method->getId();

            // --- THIS IS THE UPDATED LOGIC ---
            if ($method instanceof MicrosoftAuthenticatorAuthenticationMethod) {
                $displayName = $method->getDevice() ? ($method->getDevice()->getDisplayName() ?? 'Authenticator App') : 'Authenticator App (No Device Name)';
                $type = 'Microsoft Authenticator';
            } elseif ($method instanceof Fido2AuthenticationMethod) {
                $displayName = $method->getDisplayName() ?? 'Security Key';
                $type = 'FIDO2 Security Key';
            } elseif ($method instanceof SoftwareOathAuthenticationMethod) {
                $displayName = 'Third-Party Authenticator';
                $type = 'Software OATH Token';
            }
            
            if ($displayName !== null) {
                $stmt->execute([$userId, $deviceId, $displayName, $type]);
            }
        }
    }
    
    private function logExists(string $entraLogId): bool {
        $stmt = $this->db->prepare("SELECT 1 FROM login_logs WHERE entra_log_id = :id");
        $stmt->execute(['id' => $entraLogId]);
        return $stmt->fetchColumn() !== false;
    }
    
    private function getPreviousLoginsInLast24Hours(string $userId, string $currentLoginTime): array {
        $stmt = $this->db->prepare("SELECT * FROM login_logs WHERE user_id = :userId AND login_time < :currentLoginTime AND login_time >= :time24HoursAgo ORDER BY login_time DESC");
        $twentyFourHoursAgo = (new DateTime($currentLoginTime))->modify('-24 hours')->format('Y-m-d H:i:s');
        $stmt->execute(['userId' => $userId, 'currentLoginTime' => $currentLoginTime, 'time24HoursAgo' => $twentyFourHoursAgo]);
        return $stmt->fetchAll() ?: [];
    }
    
    private function saveLoginLog(array $data): int {
        $data['is_impossible_travel'] = (int)($data['is_impossible_travel'] ?? false);
        $data['is_region_change'] = (int)($data['is_region_change'] ?? false);
        $sql = "INSERT INTO login_logs (entra_log_id, user_id, user_principal_name, ip_address, login_time, status, country, region, city, lat, lon, is_impossible_travel, is_region_change, travel_speed_kph, previous_log_id) VALUES (:entra_log_id, :user_id, :user_principal_name, :ip_address, :login_time, :status, :country, :region, :city, :lat, :lon, :is_impossible_travel, :is_region_change, :travel_speed_kph, :previous_log_id)";
        $stmt = $this->db->prepare($sql);
        $stmt->execute($data);
        return (int)$this->db->lastInsertId();
    }
    
    private function calculateDistance(?float $lat1, ?float $lon1, ?float $lat2, ?float $lon2): float {
        if ($lat1 === null || $lon1 === null || $lat2 === null || $lon2 === null) return 0;
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
