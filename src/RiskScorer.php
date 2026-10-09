<?php
namespace App;

use PDO;
use DateTime;
use DateTimeZone;

/**
 * Turns raw sign-in activity into weighted risk signals ("risk events") and rolls
 * them up into a per-user score and tier.
 *
 * Two kinds of signal are produced:
 *  - Per-login signals: impossible travel, a value that is new for this user
 *    (country, ISP, device, app), a proxy/hosting IP, legacy authentication,
 *    and Entra ID Protection's own risk rating.
 *  - Sequence signals: brute force then success, MFA fatigue then success,
 *    password spray, and an MFA device change close to an anomalous sign-in.
 *
 * Everything is deterministic and works from rows in the database, so the same
 * code scores live logs (LogProcessor) and historical ones (rebuild_risk.php).
 * Scoring never changes whether or when emails are sent.
 */
class RiskScorer {
    public const TIERS = ['critical', 'high', 'medium', 'low'];

    /** Default weights. Override any of them with a 'RISK_WEIGHTS' array in secrets.php. */
    public const SIGNALS = [
        'IMPOSSIBLE_TRAVEL'     => ['weight' => 40, 'label' => 'Impossible travel'],
        'REGION_CHANGE'         => ['weight' => 10, 'label' => 'Region change'],
        'NEW_COUNTRY'           => ['weight' => 25, 'label' => 'New country'],
        'NEW_ISP'               => ['weight' => 10, 'label' => 'New ISP'],
        'NEW_DEVICE'            => ['weight' => 10, 'label' => 'New device or browser'],
        'NEW_APP'               => ['weight' => 5,  'label' => 'New application'],
        'PROXY_OR_HOSTING_IP'   => ['weight' => 20, 'label' => 'Proxy / hosting IP'],
        'LEGACY_AUTH'           => ['weight' => 15, 'label' => 'Legacy authentication'],
        'ENTRA_RISK_HIGH'       => ['weight' => 40, 'label' => 'Entra risk: high'],
        'ENTRA_RISK_MEDIUM'     => ['weight' => 20, 'label' => 'Entra risk: medium'],
        'ENTRA_RISK_LOW'        => ['weight' => 5,  'label' => 'Entra risk: low'],
        'BRUTE_FORCE_ATTEMPT'   => ['weight' => 15, 'label' => 'Repeated password failures'],
        'BRUTE_FORCE_SUCCESS'   => ['weight' => 55, 'label' => 'Password guessing then success'],
        'MFA_FATIGUE_ATTEMPT'   => ['weight' => 25, 'label' => 'Repeated MFA denials'],
        'MFA_FATIGUE_SUCCESS'   => ['weight' => 70, 'label' => 'MFA fatigue then success'],
        'PASSWORD_SPRAY_TARGET' => ['weight' => 15, 'label' => 'Target of password spray'],
        'SPRAY_SOURCE_SUCCESS'  => ['weight' => 55, 'label' => 'Success from password-spray source'],
        'MFA_DEVICE_ADDED'      => ['weight' => 20, 'label' => 'MFA device added'],
        'MFA_DEVICE_REMOVED'    => ['weight' => 10, 'label' => 'MFA device removed'],
        'MFA_CHANGE_CORRELATED' => ['weight' => 50, 'label' => 'MFA change near anomalous sign-in'],
    ];

    /** A user showing any of these is critical regardless of the numeric score. */
    private const FORCE_CRITICAL = ['MFA_FATIGUE_SUCCESS', 'MFA_CHANGE_CORRELATED'];

    private const LEGACY_CLIENTS = [
        'imap4', 'pop3', 'authenticated smtp', 'exchange activesync', 'other clients', 'outlook anywhere (rpc over http)',
    ];

    // Entra error codes: 50126 bad password, 50053 locked out, 500121 MFA failed/denied.
    private const PASSWORD_FAILURE_SQL = "(status LIKE 'Failure%' AND (error_code IN (50126, 50053) OR (error_code IS NULL AND status LIKE '%password%')))";
    private const MFA_DENIAL_CODE = 500121;

    private PDO $db;
    private array $whitelist = [];
    private array $weightOverrides = [];

    private int $windowHours;
    private array $tierThresholds;
    private int $baselineMinLogins;
    private int $baselineConfirmDays;
    private int $baselineRetentionDays;
    private int $bruteForceFailures;
    private int $mfaFatigueDenials;
    private int $sprayMinUsers;
    private float $regionIgnoreKm;

    public function __construct(?PDO $db = null) {
        $this->db = $db ?? Database::getInstance();
        $this->whitelist = $this->db->query("SELECT ip_address FROM ip_whitelist")->fetchAll(PDO::FETCH_COLUMN, 0);

        $this->windowHours           = (int)$this->cfg('RISK_WINDOW_HOURS', 24);
        $this->tierThresholds        = [
            'critical' => (int)$this->cfg('RISK_TIER_CRITICAL', 80),
            'high'     => (int)$this->cfg('RISK_TIER_HIGH', 55),
            'medium'   => (int)$this->cfg('RISK_TIER_MEDIUM', 30),
            'low'      => (int)$this->cfg('RISK_TIER_LOW', 15),
        ];
        $this->baselineMinLogins     = (int)$this->cfg('BASELINE_MIN_LOGINS', 10);
        $this->baselineConfirmDays   = (int)$this->cfg('BASELINE_CONFIRM_DAYS', 2);
        $this->baselineRetentionDays = (int)$this->cfg('BASELINE_RETENTION_DAYS', 90);
        $this->bruteForceFailures    = (int)$this->cfg('RISK_BRUTE_FORCE_FAILURES', 5);
        $this->mfaFatigueDenials     = (int)$this->cfg('RISK_MFA_FATIGUE_DENIALS', 4);
        $this->sprayMinUsers         = (int)$this->cfg('RISK_SPRAY_MIN_USERS', 5);
        $this->regionIgnoreKm        = (float)$this->cfg('REGION_CHANGE_IGNORE_KM', 80);

        $overrides = $_ENV['RISK_WEIGHTS'] ?? [];
        $this->weightOverrides = is_array($overrides) ? $overrides : [];
    }

    // ---------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------

    /**
     * Scores one saved sign-in (a login_logs row, including its 'id') and then
     * folds it into the user's baseline. Returns the codes of the signals that
     * applied to this sign-in.
     */
    public function scoreLogin(array $log): array {
        $success = ($log['status'] ?? '') === 'Success';
        $ip = (string)($log['ip_address'] ?? '');
        $whitelisted = $this->isWhitelisted($ip);
        $userId = $log['user_id'];
        $time = $log['login_time'];
        $day = substr($time, 0, 10);
        $hour = substr($time, 0, 13);
        $logKey = 'log:' . ($log['id'] ?? $log['entra_log_id'] ?? $time);
        $applied = [];
        $anomalyWeight = 0; // weight of signals that suggest a compromised session; drives MFA correlation

        $fire = function (string $code, string $description, string $dedupeKey, array $details = [], bool $anomaly = false) use ($log, &$applied, &$anomalyWeight) {
            $applied[] = $code;
            if ($anomaly) {
                $anomalyWeight += $this->weightFor($code);
            }
            $this->recordEvent($log, $code, $description, $dedupeKey, $details);
        };

        if ($success) {
            // --- Entra ID Protection's own verdict ---
            $riskLevel = strtolower((string)($log['risk_level_during_signin'] ?? ''));
            if (in_array($riskLevel, ['high', 'medium', 'low'], true)) {
                $fire('ENTRA_RISK_' . strtoupper($riskLevel),
                    "Entra ID Protection rated this sign-in {$riskLevel} risk" . $this->riskStateSuffix($log),
                    $logKey, ['risk_level' => $riskLevel, 'risk_state' => $log['risk_state'] ?? null], $riskLevel !== 'low');
            }

            // --- Travel flags already computed by LogProcessor ---
            if (!empty($log['is_impossible_travel']) || !empty($log['is_region_change'])) {
                $previous = $this->fetchLog($log['previous_log_id'] ?? null);
                if ($previous && ($previous['status'] ?? '') === 'Success' && !$whitelisted && !$this->isWhitelisted($previous['ip_address'])) {
                    $km = self::distanceKm($this->f($previous['lat']), $this->f($previous['lon']), $this->f($log['lat']), $this->f($log['lon']));
                    $hours = max((strtotime($time) - strtotime($previous['login_time'])) / 3600, 0);
                    $from = $this->place($previous);
                    $to = $this->place($log);
                    if (!empty($log['is_impossible_travel'])) {
                        $fire('IMPOSSIBLE_TRAVEL',
                            sprintf('%s to %s (%d km in %s, ~%d km/h)', $from, $to, $km, $this->duration($hours), (float)($log['travel_speed_kph'] ?? 0)),
                            $logKey, ['from' => $from, 'to' => $to, 'distance_km' => round($km), 'speed_kph' => round((float)($log['travel_speed_kph'] ?? 0)), 'previous_ip' => $previous['ip_address']], true);
                    } elseif ($km > $this->regionIgnoreKm) {
                        $fire('REGION_CHANGE',
                            sprintf('%s to %s (%d km apart)', $from, $to, $km),
                            $logKey, ['from' => $from, 'to' => $to, 'distance_km' => round($km), 'previous_ip' => $previous['ip_address']]);
                    }
                }
            }

            // --- Novelty against this user's baseline ---
            $mature = $this->isMature($userId, $time);
            $country = $this->clean($log['country'] ?? null);
            $isp = $this->clean($log['isp'] ?? null);
            $deviceKey = $this->deviceKey($log);
            $app = $this->clean($log['app_display_name'] ?? null);
            $clientApp = $this->clean($log['client_app_used'] ?? null);

            $ispKnown = true;
            if ($isp !== null) {
                $ispState = $this->baselineState($userId, 'isp', $isp, $time);
                $ispKnown = !$ispState['has_confirmed'] || $ispState['value_confirmed'];
            }

            if ($mature && !$whitelisted && $country !== null) {
                $state = $this->baselineState($userId, 'country', $country, $time);
                if ($state['has_confirmed'] && !$state['value_confirmed']) {
                    $usual = $this->usualValues($userId, 'country', $time);
                    $fire('NEW_COUNTRY', "Signed in from {$country}" . ($usual ? ' (usually ' . implode(', ', $usual) . ')' : ''),
                        "country:{$country}:{$day}", ['country' => $country, 'usual' => $usual, 'ip' => $ip], true);
                }
            }
            if ($mature && !$whitelisted && $isp !== null && !$ispKnown) {
                $usual = $this->usualValues($userId, 'isp', $time);
                $fire('NEW_ISP', "Signed in via {$isp}" . ($usual ? ' (usually ' . implode(', ', $usual) . ')' : ''),
                    "isp:{$isp}:{$day}", ['isp' => $isp, 'usual' => $usual, 'ip' => $ip]);
            }
            if ($mature && $deviceKey !== null) {
                $state = $this->baselineState($userId, 'device', $deviceKey, $time);
                if ($state['has_confirmed'] && !$state['value_confirmed']) {
                    $fire('NEW_DEVICE', 'Signed in from an unfamiliar device or browser: ' . ($log['device_display_name'] ?: $deviceKey),
                        "device:{$deviceKey}:{$day}", ['device' => $deviceKey, 'os' => $log['device_os'] ?? null, 'browser' => $log['device_browser'] ?? null]);
                }
            }
            if ($mature && $app !== null) {
                $state = $this->baselineState($userId, 'app', $app, $time);
                if ($state['has_confirmed'] && !$state['value_confirmed']) {
                    $fire('NEW_APP', "First time using {$app}", "app:{$app}:{$day}", ['app' => $app]);
                }
            }

            // --- IP reputation ---
            if (!$whitelisted && (!empty($log['is_proxy']) || !empty($log['is_hosting'])) && !$ispKnown) {
                $kind = !empty($log['is_hosting']) ? 'hosting provider' : 'proxy/VPN';
                $fire('PROXY_OR_HOSTING_IP', "Signed in from a {$kind} IP" . ($isp ? " ({$isp})" : ''),
                    "ip:{$ip}:{$day}", ['ip' => $ip, 'isp' => $isp, 'proxy' => !empty($log['is_proxy']), 'hosting' => !empty($log['is_hosting'])], true);
            }

            // --- Legacy authentication ---
            if ($clientApp !== null && in_array(strtolower($clientApp), self::LEGACY_CLIENTS, true)) {
                $state = $this->baselineState($userId, 'client_app', $clientApp, $time);
                if (!$state['value_confirmed']) {
                    $fire('LEGACY_AUTH', "Signed in with legacy protocol {$clientApp}", "legacy:{$clientApp}:{$day}", ['client_app' => $clientApp, 'ip' => $ip]);
                }
            }

            // --- Failures followed by this success ---
            $from = $this->shift($time, '-60 minutes');
            if (!$whitelisted) {
                $sameIpFailures = $this->countPasswordFailures($userId, $ip, $from, $time);
                $novelty = in_array('NEW_COUNTRY', $applied, true) || in_array('NEW_ISP', $applied, true) || in_array('NEW_DEVICE', $applied, true);
                if ($sameIpFailures >= $this->bruteForceFailures && ($novelty || $sameIpFailures >= $this->bruteForceFailures * 2)) {
                    $fire('BRUTE_FORCE_SUCCESS', "Signed in after {$sameIpFailures} failed password attempts from {$ip} in the previous hour",
                        $logKey, ['failures' => $sameIpFailures, 'ip' => $ip], true);
                }
                $sprayUsers = $this->countSprayUsers($ip, $from, $time);
                if ($sprayUsers >= $this->sprayMinUsers) {
                    $fire('SPRAY_SOURCE_SUCCESS', "Signed in from {$ip}, which failed against {$sprayUsers} different accounts in the last hour",
                        $logKey, ['ip' => $ip, 'targeted_users' => $sprayUsers], true);
                }
            }
            $denials = $this->countMfaDenials($userId, $this->shift($time, '-30 minutes'), $time);
            if ($denials >= $this->mfaFatigueDenials) {
                $fire('MFA_FATIGUE_SUCCESS', "MFA approved after {$denials} denied or ignored prompts in the previous 30 minutes",
                    $logKey, ['denials' => $denials, 'ip' => $ip], true);
            }

            // --- MFA device change close to an anomalous sign-in ---
            if ($anomalyWeight >= 20) {
                $this->correlateWithDeviceChanges($log, $anomalyWeight);
            }
        } elseif (!$whitelisted || $this->isMfaDenial($log)) {
            // --- Failure patterns ---
            if ($this->isPasswordFailure($log) && !$whitelisted) {
                $failures = $this->countPasswordFailures($userId, null, $this->shift($time, '-60 minutes'), $time);
                if ($failures >= $this->bruteForceFailures) {
                    $fire('BRUTE_FORCE_ATTEMPT', "{$failures} failed password attempts in the last hour",
                        "brute:{$hour}", ['failures' => $failures]);
                }
                $targets = $this->sprayTargets($ip, $this->shift($time, '-60 minutes'), $time);
                if (count($targets) >= $this->sprayMinUsers) {
                    // Once the pattern is clear, every account the source hit is a target, not just the latest.
                    $applied[] = 'PASSWORD_SPRAY_TARGET';
                    foreach ($targets as $target) {
                        $this->recordEvent(
                            ['user_id' => $target['user_id'], 'user_principal_name' => $target['user_principal_name'], 'login_time' => $time, 'ip_address' => $ip],
                            'PASSWORD_SPRAY_TARGET',
                            "Targeted by password spray from {$ip} (" . count($targets) . " accounts in the last hour)",
                            "spray:{$ip}:{$hour}",
                            ['ip' => $ip, 'targeted_users' => count($targets)]
                        );
                    }
                }
            }
            if ($this->isMfaDenial($log)) {
                $denials = $this->countMfaDenials($userId, $this->shift($time, '-30 minutes'), $time);
                if ($denials >= $this->mfaFatigueDenials) {
                    $fire('MFA_FATIGUE_ATTEMPT', "{$denials} MFA prompts denied or ignored in the last 30 minutes",
                        "mfaf:{$hour}", ['denials' => $denials]);
                }
            }
        }

        if ($success) {
            $this->learn($log);
        }

        return $applied;
    }

    /**
     * Scores a row of auth_device_changes. The caller must only pass changes
     * for users that already had a device snapshot, otherwise the first run for
     * a new user would report every existing device as newly added.
     */
    public function scoreDeviceChange(int $changeId): array {
        $stmt = $this->db->prepare("SELECT * FROM auth_device_changes WHERE id = ?");
        $stmt->execute([$changeId]);
        $change = $stmt->fetch();
        if (!$change) {
            return [];
        }

        $added = strtolower($change['change_type']) === 'added';
        $code = $added ? 'MFA_DEVICE_ADDED' : 'MFA_DEVICE_REMOVED';
        $this->recordEvent(
            ['user_id' => $change['user_id'], 'user_principal_name' => $change['user_principal_name'], 'login_time' => $change['change_time']],
            $code,
            ($added ? 'Added' : 'Removed') . ' MFA device: ' . $change['device_display_name'],
            "devchg:{$changeId}",
            ['device' => $change['device_display_name']],
            null,
            $changeId
        );
        $applied = [$code];

        // Was there an anomalous sign-in in the 24h before this change?
        $stmt = $this->db->prepare(
            "SELECT signal_code, description FROM risk_events
             WHERE user_id = ? AND occurred_at BETWEEN ? AND ? AND weight >= 20
               AND signal_code NOT IN ('MFA_DEVICE_ADDED', 'MFA_DEVICE_REMOVED', 'MFA_CHANGE_CORRELATED', 'PASSWORD_SPRAY_TARGET', 'MFA_FATIGUE_ATTEMPT', 'BRUTE_FORCE_ATTEMPT')
             ORDER BY weight DESC LIMIT 1"
        );
        $stmt->execute([$change['user_id'], $this->shift($change['change_time'], '-24 hours'), $change['change_time']]);
        $anomaly = $stmt->fetch();
        if ($anomaly) {
            $this->recordCorrelation($change, $anomaly['description']);
            $applied[] = 'MFA_CHANGE_CORRELATED';
        }
        return $applied;
    }

    /** Rebuilds one user's rolled-up score from the events inside the scoring window. */
    public function recomputeUserScore(string $userId, ?string $runTime = null): ?array {
        $runTime = $runTime ?? gmdate('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            "SELECT signal_code, MAX(weight) AS max_weight, COUNT(*) AS occurrences, MAX(occurred_at) AS last_at, MAX(user_principal_name) AS upn
             FROM risk_events WHERE user_id = ? AND occurred_at >= ? GROUP BY signal_code"
        );
        $stmt->execute([$userId, $this->shift($runTime, "-{$this->windowHours} hours")]);
        $rows = $stmt->fetchAll();

        if (!$rows) {
            $this->db->prepare("DELETE FROM user_risk_scores WHERE user_id = ?")->execute([$userId]);
            return null;
        }

        $score = 0.0;
        $signals = [];
        $eventCount = 0;
        $lastAt = null;
        $forced = false;
        foreach ($rows as $row) {
            $weight = (int)$row['max_weight'];
            $count = (int)$row['occurrences'];
            // Repeats of the same signal add a quarter of its weight each, up to three extra times.
            $score += $weight + $weight * 0.25 * min($count - 1, 3);
            $eventCount += $count;
            $lastAt = max($lastAt ?? '', $row['last_at']);
            $forced = $forced || in_array($row['signal_code'], self::FORCE_CRITICAL, true);
            $signals[] = [
                'code' => $row['signal_code'],
                'label' => self::SIGNALS[$row['signal_code']]['label'] ?? $row['signal_code'],
                'weight' => $weight,
                'count' => $count,
            ];
        }
        usort($signals, fn($a, $b) => $b['weight'] <=> $a['weight']);

        $score = (int)min(100, round($score));
        $tier = $this->tierFor($score, $forced);
        if ($tier === null) {
            $this->db->prepare("DELETE FROM user_risk_scores WHERE user_id = ?")->execute([$userId]);
            return null;
        }
        if ($forced) {
            $score = max($score, $this->tierThresholds['critical']);
        }

        $this->db->prepare(
            "INSERT INTO user_risk_scores (user_id, user_principal_name, score, tier, signals, event_count, last_event_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE user_principal_name = VALUES(user_principal_name), score = VALUES(score), tier = VALUES(tier),
                signals = VALUES(signals), event_count = VALUES(event_count), last_event_at = VALUES(last_event_at), updated_at = VALUES(updated_at)"
        )->execute([$userId, $rows[0]['upn'], $score, $tier, json_encode($signals), $eventCount, $lastAt, $runTime]);

        return ['user_id' => $userId, 'upn' => $rows[0]['upn'], 'score' => $score, 'tier' => $tier, 'signals' => $signals];
    }

    /**
     * Recomputes every user with events in the window and drops scores that have
     * aged out. Returns a tier => user count map.
     */
    public function refreshAllScores(): array {
        $runTime = gmdate('Y-m-d H:i:s');
        $stmt = $this->db->prepare("SELECT DISTINCT user_id FROM risk_events WHERE occurred_at >= ?");
        $stmt->execute([$this->shift($runTime, "-{$this->windowHours} hours")]);

        $counts = array_fill_keys(self::TIERS, 0);
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN, 0) as $userId) {
            $result = $this->recomputeUserScore($userId, $runTime);
            if ($result) {
                $counts[$result['tier']]++;
            }
        }
        $this->db->prepare("DELETE FROM user_risk_scores WHERE updated_at < ?")->execute([$runTime]);
        return $counts;
    }

    /** Trims risk events and baseline values that have outlived their usefulness. */
    public function pruneOldData(): array {
        $events = $this->db->prepare("DELETE FROM risk_events WHERE occurred_at < ?");
        $events->execute([gmdate('Y-m-d H:i:s', strtotime('-180 days'))]);
        $baselines = $this->db->prepare("DELETE FROM user_baselines WHERE last_seen < ?");
        $baselines->execute([gmdate('Y-m-d H:i:s', strtotime("-{$this->baselineRetentionDays} days"))]);
        return ['risk_events' => $events->rowCount(), 'baselines' => $baselines->rowCount()];
    }

    /** Wipes all derived risk data (used before a full rebuild). */
    public function resetAll(): void {
        $this->db->exec("TRUNCATE TABLE risk_events");
        $this->db->exec("TRUNCATE TABLE user_baselines");
        $this->db->exec("TRUNCATE TABLE user_risk_scores");
    }

    public static function severityForWeight(int $weight): string {
        if ($weight >= 50) return 'critical';
        if ($weight >= 35) return 'high';
        if ($weight >= 20) return 'medium';
        return 'low';
    }

    public static function distanceKm(?float $lat1, ?float $lon1, ?float $lat2, ?float $lon2): float {
        if ($lat1 === null || $lon1 === null || $lat2 === null || $lon2 === null) return 0.0;
        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);
        $a = sin($dLat / 2) ** 2 + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon / 2) ** 2;
        return 6371 * 2 * atan2(sqrt($a), sqrt(1 - $a));
    }

    // ---------------------------------------------------------------------
    // Baselines
    // ---------------------------------------------------------------------

    /** Folds a successful sign-in into the user's profile of "normal". */
    private function learn(array $log): void {
        $values = [
            'country'    => $this->clean($log['country'] ?? null),
            'isp'        => $this->clean($log['isp'] ?? null),
            'app'        => $this->clean($log['app_display_name'] ?? null),
            'device'     => $this->deviceKey($log),
            'client_app' => $this->clean($log['client_app_used'] ?? null),
        ];
        $stmt = $this->db->prepare(
            "INSERT INTO user_baselines (user_id, dimension, value, seen_count, days_seen, first_seen, last_seen)
             VALUES (?, ?, ?, 1, 1, ?, ?)
             ON DUPLICATE KEY UPDATE
                days_seen = days_seen + IF(DATE(last_seen) < DATE(VALUES(last_seen)), 1, 0),
                seen_count = seen_count + 1,
                last_seen = GREATEST(last_seen, VALUES(last_seen))"
        );
        foreach ($values as $dimension => $value) {
            if ($value !== null) {
                $stmt->execute([$log['user_id'], $dimension, $value, $log['login_time'], $log['login_time']]);
            }
        }
    }

    /**
     * A user has a usable baseline once they have enough successful sign-ins
     * spread over more than a couple of days. Before that, "new" means nothing.
     */
    private function isMature(string $userId, string $time): bool {
        $stmt = $this->db->prepare(
            "SELECT COUNT(*) AS c, MIN(login_time) AS first_login FROM login_logs
             WHERE user_id = ? AND status = 'Success' AND login_time < ? AND login_time >= ?"
        );
        $stmt->execute([$userId, $time, $this->shift($time, "-{$this->baselineRetentionDays} days")]);
        $row = $stmt->fetch();
        return (int)$row['c'] >= $this->baselineMinLogins
            && $row['first_login'] !== null
            && strtotime($row['first_login']) <= strtotime($time) - $this->baselineConfirmDays * 86400;
    }

    /**
     * has_confirmed: the user has at least one established value in this dimension
     *   (without one we cannot call anything unusual).
     * value_confirmed: this specific value is established.
     */
    private function baselineState(string $userId, string $dimension, string $value, string $time): array {
        $stmt = $this->db->prepare(
            "SELECT COALESCE(SUM(days_seen >= ?), 0) AS confirmed, COALESCE(SUM(value = ? AND days_seen >= ?), 0) AS value_confirmed
             FROM user_baselines WHERE user_id = ? AND dimension = ? AND last_seen >= ?"
        );
        $stmt->execute([$this->baselineConfirmDays, $value, $this->baselineConfirmDays, $userId, $dimension, $this->shift($time, "-{$this->baselineRetentionDays} days")]);
        $row = $stmt->fetch();
        return ['has_confirmed' => (int)$row['confirmed'] > 0, 'value_confirmed' => (int)$row['value_confirmed'] > 0];
    }

    private function usualValues(string $userId, string $dimension, string $time, int $limit = 3): array {
        $stmt = $this->db->prepare(
            "SELECT value FROM user_baselines WHERE user_id = ? AND dimension = ? AND days_seen >= ? AND last_seen >= ?
             ORDER BY seen_count DESC LIMIT " . (int)$limit
        );
        $stmt->execute([$userId, $dimension, $this->baselineConfirmDays, $this->shift($time, "-{$this->baselineRetentionDays} days")]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    }

    /** Registered device id when there is one, otherwise "OS / Browser" without the browser version. */
    private function deviceKey(array $log): ?string {
        $id = trim((string)($log['device_id'] ?? ''));
        if ($id !== '' && $id !== '00000000-0000-0000-0000-000000000000') {
            return $this->clean($id);
        }
        $os = trim((string)($log['device_os'] ?? ''));
        $browser = trim(preg_replace('/\s+[\d.]+$/', '', (string)($log['device_browser'] ?? '')));
        $key = trim($os . ' / ' . $browser, ' /');
        return $key === '' ? null : $this->clean($key);
    }

    // ---------------------------------------------------------------------
    // Event storage and sequence queries
    // ---------------------------------------------------------------------

    private function recordEvent(array $log, string $code, string $description, string $dedupeKey, array $details = [], ?int $logId = null, ?int $changeId = null): bool {
        $stmt = $this->db->prepare(
            "INSERT IGNORE INTO risk_events (user_id, user_principal_name, signal_code, weight, login_log_id, device_change_id, ip_address, description, details, occurred_at, dedupe_key)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            $log['user_id'],
            $log['user_principal_name'],
            $code,
            $this->weightFor($code),
            $logId ?? (isset($log['id']) ? (int)$log['id'] : null),
            $changeId,
            $log['ip_address'] ?? null,
            mb_substr($description, 0, 500),
            $details ? json_encode($details) : null,
            $log['login_time'],
            mb_substr($dedupeKey, 0, 190),
        ]);
        return $stmt->rowCount() > 0;
    }

    private function correlateWithDeviceChanges(array $log, int $anomalyWeight): void {
        $stmt = $this->db->prepare(
            "SELECT * FROM auth_device_changes WHERE user_id = ? AND change_time BETWEEN ? AND ?"
        );
        $stmt->execute([$log['user_id'], $this->shift($log['login_time'], '-24 hours'), $this->shift($log['login_time'], '+24 hours')]);
        foreach ($stmt->fetchAll() as $change) {
            $this->recordCorrelation($change, 'Anomalous sign-in from ' . ($log['ip_address'] ?? 'unknown IP') . ' at ' . $log['login_time'] . ' UTC');
        }
    }

    private function recordCorrelation(array $change, string $anomalyDescription): void {
        $this->recordEvent(
            ['user_id' => $change['user_id'], 'user_principal_name' => $change['user_principal_name'], 'login_time' => $change['change_time']],
            'MFA_CHANGE_CORRELATED',
            strtolower($change['change_type']) . ' MFA device "' . $change['device_display_name'] . '" within 24h of: ' . $anomalyDescription,
            'mfacorr:' . $change['id'],
            ['device' => $change['device_display_name'], 'change' => $change['change_type']],
            null,
            (int)$change['id']
        );
    }

    private function countPasswordFailures(string $userId, ?string $ip, string $from, string $to): int {
        $sql = "SELECT COUNT(*) FROM login_logs WHERE user_id = ? AND login_time BETWEEN ? AND ? AND " . self::PASSWORD_FAILURE_SQL;
        $params = [$userId, $from, $to];
        if ($ip !== null) {
            $sql .= " AND ip_address = ?";
            $params[] = $ip;
        }
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return (int)$stmt->fetchColumn();
    }

    private function countSprayUsers(string $ip, string $from, string $to): int {
        $stmt = $this->db->prepare("SELECT COUNT(DISTINCT user_id) FROM login_logs WHERE ip_address = ? AND login_time BETWEEN ? AND ? AND " . self::PASSWORD_FAILURE_SQL);
        $stmt->execute([$ip, $from, $to]);
        return (int)$stmt->fetchColumn();
    }

    private function sprayTargets(string $ip, string $from, string $to): array {
        $stmt = $this->db->prepare("SELECT user_id, MAX(user_principal_name) AS user_principal_name FROM login_logs WHERE ip_address = ? AND login_time BETWEEN ? AND ? AND " . self::PASSWORD_FAILURE_SQL . " GROUP BY user_id");
        $stmt->execute([$ip, $from, $to]);
        return $stmt->fetchAll();
    }

    private function countMfaDenials(string $userId, string $from, string $to): int {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM login_logs WHERE user_id = ? AND login_time BETWEEN ? AND ? AND error_code = ?");
        $stmt->execute([$userId, $from, $to, self::MFA_DENIAL_CODE]);
        return (int)$stmt->fetchColumn();
    }

    private function isPasswordFailure(array $log): bool {
        $status = (string)($log['status'] ?? '');
        if (!str_starts_with($status, 'Failure')) return false;
        $code = $log['error_code'] ?? null;
        return $code === null ? stripos($status, 'password') !== false : in_array((int)$code, [50126, 50053], true);
    }

    private function isMfaDenial(array $log): bool {
        return str_starts_with((string)($log['status'] ?? ''), 'Failure') && (int)($log['error_code'] ?? 0) === self::MFA_DENIAL_CODE;
    }

    // ---------------------------------------------------------------------
    // Scoring helpers
    // ---------------------------------------------------------------------

    private function tierFor(int $score, bool $forceCritical): ?string {
        if ($forceCritical) return 'critical';
        foreach (self::TIERS as $tier) {
            if ($score >= $this->tierThresholds[$tier]) return $tier;
        }
        return null;
    }

    private function weightFor(string $code): int {
        return (int)($this->weightOverrides[$code] ?? self::SIGNALS[$code]['weight'] ?? 0);
    }

    private function riskStateSuffix(array $log): string {
        $state = $log['risk_state'] ?? null;
        return ($state && strtolower($state) !== 'none') ? " ({$state})" : '';
    }

    private function isWhitelisted(?string $ip): bool {
        return $ip !== null && in_array($ip, $this->whitelist, true);
    }

    private function fetchLog($id): ?array {
        if (empty($id)) return null;
        $stmt = $this->db->prepare("SELECT * FROM login_logs WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch() ?: null;
    }

    private function place(array $log): string {
        $parts = array_filter([$log['city'] ?? null, $log['country'] ?? null]);
        return $parts ? implode(', ', $parts) : ($log['ip_address'] ?? 'unknown');
    }

    private function duration(float $hours): string {
        return $hours < 1 ? max(1, (int)round($hours * 60)) . ' min' : round($hours, 1) . ' h';
    }

    private function shift(string $time, string $modifier): string {
        return (new DateTime($time, new DateTimeZone('UTC')))->modify($modifier)->format('Y-m-d H:i:s');
    }

    private function clean($value): ?string {
        $value = trim((string)$value);
        return $value === '' ? null : mb_substr($value, 0, 255);
    }

    private function f($value): ?float {
        return ($value === null || $value === '') ? null : (float)$value;
    }

    private function cfg(string $key, $default) {
        $value = $_ENV[$key] ?? null;
        return ($value === null || $value === '') ? $default : $value;
    }
}
