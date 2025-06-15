<?php
namespace App;

use PDO;

class Auth {
    private PDO $db;

    public function __construct() {
        // The session is started in index.php, so we just check here.
        if (session_status() === PHP_SESSION_NONE) {
            // This is a fallback, but the primary session_start() should be the one in index.php
            session_start();
        }
        $this->db = Database::getInstance();
    }

    public function login(string $username, string $password): bool {
        $stmt = $this->db->prepare("SELECT * FROM admins WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password_hash'])) {
            // This sets the session variable correctly.
            $_SESSION['admin_id'] = $user['id'];
            $_SESSION['admin_username'] = $user['username'];
            return true;
        }
        return false;
    }

    public function check(): bool {
        return isset($_SESSION['admin_id']);
    }

    public function logout(): void {
        session_unset();
        session_destroy();
        // It's good practice to also clear the session cookie.
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    public function getUsername(): ?string {
        return $_SESSION['admin_username'] ?? null;
    }
}