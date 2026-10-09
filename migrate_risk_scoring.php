#!/usr/bin/env php
<?php
// One-time (and safe to re-run) migration for existing installs. It adds the
// sign-in context columns used by risk scoring and creates the baseline, risk
// event and risk score tables. Fresh installs get all of this from dbsetup.txt.

if (php_sapi_name() !== 'cli') {
    die('This script can only be run from the command line.');
}

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
}

use App\Database;

$db = Database::getInstance();

function columnExists(PDO $db, string $table, string $column): bool {
    $stmt = $db->prepare("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?");
    $stmt->execute([$table, $column]);
    return $stmt->fetchColumn() !== false;
}

function indexExists(PDO $db, string $table, string $index): bool {
    $stmt = $db->prepare("SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?");
    $stmt->execute([$table, $index]);
    return $stmt->fetchColumn() !== false;
}

$columns = [
    'login_logs' => [
        'error_code' => 'INT NULL',
        'app_display_name' => 'VARCHAR(255) NULL',
        'resource_display_name' => 'VARCHAR(255) NULL',
        'client_app_used' => 'VARCHAR(100) NULL',
        'device_id' => 'VARCHAR(100) NULL',
        'device_display_name' => 'VARCHAR(255) NULL',
        'device_os' => 'VARCHAR(100) NULL',
        'device_browser' => 'VARCHAR(255) NULL',
        'is_compliant' => 'TINYINT(1) NULL',
        'is_managed' => 'TINYINT(1) NULL',
        'is_interactive' => 'TINYINT(1) NULL',
        'conditional_access_status' => 'VARCHAR(50) NULL',
        'risk_level_during_signin' => 'VARCHAR(30) NULL',
        'risk_state' => 'VARCHAR(50) NULL',
        'isp' => 'VARCHAR(255) NULL',
        'is_proxy' => 'TINYINT(1) NULL',
        'is_hosting' => 'TINYINT(1) NULL',
    ],
    'ip_geolocation_cache' => [
        'is_proxy' => 'TINYINT(1) NULL',
        'is_hosting' => 'TINYINT(1) NULL',
    ],
];

foreach ($columns as $table => $defs) {
    foreach ($defs as $column => $definition) {
        if (columnExists($db, $table, $column)) {
            echo "  [skip] $table.$column already exists\n";
            continue;
        }
        $db->exec("ALTER TABLE `$table` ADD COLUMN `$column` $definition");
        echo "  [add]  $table.$column\n";
    }
}

$indexes = [
    ['login_logs', 'user_time_idx', '(`user_id`, `login_time`)'],
    ['login_logs', 'ip_time_idx', '(`ip_address`, `login_time`)'],
];
foreach ($indexes as [$table, $index, $definition]) {
    if (indexExists($db, $table, $index)) {
        echo "  [skip] index $table.$index already exists\n";
        continue;
    }
    $db->exec("ALTER TABLE `$table` ADD INDEX `$index` $definition");
    echo "  [add]  index $table.$index\n";
}

$db->exec("CREATE TABLE IF NOT EXISTS `user_baselines` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` VARCHAR(255) NOT NULL,
  `dimension` VARCHAR(20) NOT NULL,
  `value` VARCHAR(255) NOT NULL,
  `seen_count` INT NOT NULL DEFAULT 1,
  `days_seen` INT NOT NULL DEFAULT 1,
  `first_seen` DATETIME NOT NULL,
  `last_seen` DATETIME NOT NULL,
  UNIQUE KEY `user_dim_value_unique` (`user_id`, `dimension`, `value`),
  INDEX `last_seen_idx` (`last_seen`)
)");

$db->exec("CREATE TABLE IF NOT EXISTS `risk_events` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` VARCHAR(255) NOT NULL,
  `user_principal_name` VARCHAR(255) NOT NULL,
  `signal_code` VARCHAR(50) NOT NULL,
  `weight` SMALLINT NOT NULL,
  `login_log_id` INT NULL,
  `device_change_id` INT NULL,
  `ip_address` VARCHAR(45) NULL,
  `description` VARCHAR(500) NOT NULL,
  `details` TEXT NULL,
  `occurred_at` DATETIME NOT NULL,
  `dedupe_key` VARCHAR(190) NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `event_dedupe_unique` (`user_id`, `signal_code`, `dedupe_key`),
  INDEX `user_time_idx` (`user_id`, `occurred_at`),
  INDEX `occurred_idx` (`occurred_at`)
)");

$db->exec("CREATE TABLE IF NOT EXISTS `user_risk_scores` (
  `user_id` VARCHAR(255) PRIMARY KEY,
  `user_principal_name` VARCHAR(255) NOT NULL,
  `score` SMALLINT NOT NULL,
  `tier` VARCHAR(10) NOT NULL,
  `signals` TEXT NULL,
  `event_count` INT NOT NULL DEFAULT 0,
  `last_event_at` DATETIME NULL,
  `updated_at` DATETIME NOT NULL,
  INDEX `score_idx` (`score`)
)");
echo "  [ok]   user_baselines, risk_events, user_risk_scores\n";

echo "\nMigration complete. Existing sign-ins have no app/device/risk context, so run\n";
echo "'php rebuild_risk.php' to build baselines and risk events from the history you already have.\n";
