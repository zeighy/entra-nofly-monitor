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

    // --- Cloudflare Turnstile Configuration ---
    // Use these test keys to test the integration without real credentials
    // Site Key (Test): 1x00000000000000000000AA
    // Secret Key (Test): 1x0000000000000000000000000000000AA
    'TURNSTILE_SITE_KEY' => '1x00000000000000000000AA',
    'TURNSTILE_SECRET_KEY' => '1x0000000000000000000000000000000AA',

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

    // --- Risk Scoring (all optional; the values shown are the defaults) ---
    // Users are scored from the signals seen in the last RISK_WINDOW_HOURS and placed in a tier.
    // 'RISK_WINDOW_HOURS' => 24,
    // 'RISK_TIER_CRITICAL' => 80,
    // 'RISK_TIER_HIGH' => 55,
    // 'RISK_TIER_MEDIUM' => 30,
    // 'RISK_TIER_LOW' => 15,
    // A user's baseline needs this many successful sign-ins (spread over more than BASELINE_CONFIRM_DAYS)
    // before "new country / ISP / device / app" signals are raised. A value counts as established once it
    // has been seen on BASELINE_CONFIRM_DAYS separate days; baseline values expire after BASELINE_RETENTION_DAYS.
    // 'BASELINE_MIN_LOGINS' => 10,
    // 'BASELINE_CONFIRM_DAYS' => 2,
    // 'BASELINE_RETENTION_DAYS' => 90,
    // Sequence detection thresholds.
    // 'RISK_BRUTE_FORCE_FAILURES' => 5,   // failed passwords in 60 min
    // 'RISK_MFA_FATIGUE_DENIALS' => 4,    // denied/ignored MFA prompts in 30 min
    // 'RISK_SPRAY_MIN_USERS' => 5,        // accounts failing from one IP in 60 min
    // Override individual signal weights (see the table under Tools & help in the dashboard).
    // 'RISK_WEIGHTS' => ['NEW_COUNTRY' => 30, 'LEGACY_AUTH' => 25],

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

    // --- API Configuration ---
    // The Bearer token required to access the /api/reports.php endpoint.
    // Set to a strong, random string. If left blank, API access is disabled.
    'API_TOKEN' => 'your_secure_api_token_here',
];
