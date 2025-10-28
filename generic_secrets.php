<?php
// This file contains all your secret credentials.
// Do NOT commit this file to version control.

return [
    // --- Database Configuration ---
    'DB_HOST' => 'localhost',
    'DB_PORT' => '3306',
    'DB_DATABASE' => 'your_database_name',
    'DB_USERNAME' => 'your_database_user',
    'DB_PASSWORD' => 'your_database_password',

    // --- Microsoft Graph API Configuration ---
    'AZURE_TENANT_ID' => 'your_tenant_id',
    'AZURE_CLIENT_ID' => 'your_client_id',
    'AZURE_CLIENT_SECRET' => 'your_client_secret',

    // --- Geolocation API ---
    'IP_GEOLOCATION_API_URL' => 'http://ip-api.com/json/',

    // --- Impossible Travel Configuration ---
    // Set maximum travel speed between login locations in km/h
    'IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD' => 800,

    // Will not flag a region change if the distance is less than this value (in km).
    // This helps prevent false positives for users near a state/province border.
    // 80km is default as it iss roughly 1 hour communute for in-city driving.
    'REGION_CHANGE_IGNORE_KM' => 80,

    // --- Email Alerting Configuration ---
    'SMTP_HOST' => 'your_smtp_server.com',
    'SMTP_PORT' => 587,
    'SMTP_USERNAME' => 'your_smtp_username',
    'SMTP_PASSWORD' => 'your_smtp_password',
    'SMTP_SECURE' => 'tls',
    'SMTP_FROM_EMAIL' => 'alerts@yourdomain.com',
    'SMTP_FROM_NAME' => 'Entra Security Alerts',
    'ADMIN_ALERT_EMAIL' => 'admin@yourdomain.com', // The main "To" recipient
    'MAILER_CC_RECIPIENTS' => 'recipient1@example.com,recipient2@example.com,recipient3@example.com',

    // --- User Alert Customization ---
    // Set to true to disable all individual user security alerts.
    'DISABLE_ALL_USER_ALERTS' => false,

    // A list of user principal names (emails) who should NOT receive individual security alerts.
    // Admin consolidated alerts are not affected by this setting.
    // Example: 'user1@yourdomain.com', 'user2@yourdomain.com'
    'DISABLED_USER_ALERTS' => [],
];
