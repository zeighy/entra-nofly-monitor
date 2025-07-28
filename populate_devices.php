<?php

// This is a one-time helper script to pre-populate the user_auth_devices table
// with a snapshot of MFA-related authentication methods for every user in the tenant.
// This establishes a baseline for future change detection.

// --- Setup Log File ---
$logDir = __DIR__ . '/logs-6Tnx-HLFW';
if (!is_dir($logDir)) {
    if (!@mkdir($logDir, 0777, true) && !is_dir($logDir)) {
         die("FATAL ERROR: Could not create log directory at '$logDir'. Please check permissions.");
    }
}
$logFile = $logDir . '/device_population_' . date('Ymd-His') . '.log';
$logHandle = fopen($logFile, 'w');

function write_log($message) {
    global $logHandle;
    // Write to the console
    echo $message;
    // Write to the log file
    fwrite($logHandle, $message);
}
// --- END Log File Setup ---


write_log("--- Starting MFA Device Population Script ---\n\n");

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
use App\GraphHelper;
use Microsoft\Graph\Generated\Models\Fido2AuthenticationMethod;
use Microsoft\Graph\Generated\Models\MicrosoftAuthenticatorAuthenticationMethod;
use Microsoft\Graph\Generated\Models\SoftwareOathAuthenticationMethod;

try {
    $db = Database::getInstance();
    write_log("Database connection successful.\n");

    // Backup current user_auth_device table before removing all contents
    write_log("Backing up existing device data...\n");
    $db->exec("CREATE TABLE IF NOT EXISTS user_auth_devices_backup LIKE user_auth_devices;");
    $db->exec("TRUNCATE TABLE user_auth_devices_backup;");
    $db->exec("INSERT INTO user_auth_devices_backup SELECT * FROM user_auth_devices;");
    write_log("Backup complete.\n");

    $graphHelper = new GraphHelper();
    write_log("Fetching all users from Microsoft Entra... (This may take a moment)\n");
    $allUsers = $graphHelper->getAllUsers();
    $totalUsers = count($allUsers);

    if (empty($allUsers)) {
        write_log("No users found in the tenant. Exiting.\n");
        exit;
    }

    write_log("Found " . $totalUsers . " users. Clearing current device snapshot table...\n");
    $db->query("TRUNCATE TABLE user_auth_devices");

    $insertStmt = $db->prepare(
        "INSERT IGNORE INTO user_auth_devices (user_id, device_id, display_name, device_type) VALUES (?, ?, ?, ?)"
    );

    $userCount = 0;
    $totalDevices = 0;

    foreach ($allUsers as $user) {
        $userCount++;
        $userId = $user->getId();
        $userPrincipalName = $user->getUserPrincipalName();

        write_log("[$userCount/$totalUsers] Processing: $userPrincipalName\n");

        $authMethods = $graphHelper->getAuthMethodsForUser($userId);

        if (empty($authMethods)) {
            write_log("  No auth methods found for this user.\n");
            continue;
        }

        foreach ($authMethods as $method) {
            $displayName = null; 
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
            
            if ($displayName !== null && $type !== null) {
                $insertStmt->execute([$userId, $deviceId, $displayName, $type]);
                if ($insertStmt->rowCount() > 0) {
                    $totalDevices++;
                    write_log("  -> Found MFA device: $displayName ($type)\n");
                } else {
                    write_log("  -> Skipping duplicate MFA device from API: $displayName ($type)\n");
                }
            } else {
                $classNameParts = explode('\\', get_class($method));
                $className = end($classNameParts);
                write_log("  -> Skipping non-MFA method: $className\n");
            }
        }
    }

    write_log("\n--- Population Complete ---\n");
    write_log("Processed " . $totalUsers . " users.\n");
    write_log("Populated a total of " . $totalDevices . " unique MFA devices into the database.\n");
    write_log("Log file saved to: " . $logFile . "\n");

} catch (\Exception $e) {
    $errorMessage = "An application error occurred: " . $e->getMessage() . "\n";
    write_log($errorMessage);
    die($errorMessage);
} finally {
    if (isset($logHandle)) {
        fclose($logHandle);
    }
}
