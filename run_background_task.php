#!/usr/bin/env php
<?php

$autoloader = __DIR__ . '/vendor/autoload.php';
if (!file_exists($autoloader)) {
    die("FATAL ERROR: Composer autoloader not found at '$autoloader'.\nPlease run 'composer install' inside your project directory.\n");
}
require_once $autoloader;

// Load credentials from secrets.php
$secretsFile = __DIR__ . '/secrets.php';
if (!file_exists($secretsFile)) {
    die("FATAL ERROR: secrets.php file not found. Please create it in the project root: " . __DIR__);
}
$secrets = require $secretsFile;
foreach ($secrets as $key => $value) {
    $_ENV[$key] = $value;
    putenv("$key=$value");
}

use App\LogProcessor;

if (php_sapi_name() !== 'cli') {
    die('This script can only be run from the command line.');
}

// Validate that the necessary environment variables have been loaded
$required_vars = ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET'];
$missing_vars = [];
foreach ($required_vars as $var) {
    if (empty($_ENV[$var])) {
        $missing_vars[] = $var;
    }
}

if (!empty($missing_vars)) {
    die("FATAL ERROR: The following required variables are missing or empty in your secrets.php file: " . implode(', ', $missing_vars) . "\n");
}

try {
    $processor = new LogProcessor();
    $processor->run();
} catch (\Exception $e) {
    echo "An application error occurred: " . $e->getMessage() . "\n";
    error_log("Background task failed: " . $e->getMessage());
}