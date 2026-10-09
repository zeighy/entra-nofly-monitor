<?php
namespace App;

use PDO;

class Geolocation {
    private PDO $db;

    public function __construct() {
        $this->db = Database::getInstance();
    }

    public function getGeoInfo(string $ipAddress): ?array {
        $stmt = $this->db->prepare("SELECT * FROM ip_geolocation_cache WHERE ip_address = :ip");
        $stmt->execute(['ip' => $ipAddress]);
        $cached = $stmt->fetch();

        if ($cached) {
            return $cached;
        }

        $url = $_ENV['IP_GEOLOCATION_API_URL'] . $ipAddress;
        if (str_contains($url, 'ip-api.com')) {
            // Ask for the proxy/hosting flags that risk scoring uses (free tier, same quota).
            $url .= '?fields=status,message,country,regionName,city,lat,lon,isp,proxy,hosting';
        }
        $responseJson = @file_get_contents($url);
        if ($responseJson === false) {
            return null;
        }

        $data = json_decode($responseJson, true);

        if ($data && $data['status'] === 'success') {
            $data['is_proxy'] = isset($data['proxy']) ? (int)$data['proxy'] : null;
            $data['is_hosting'] = isset($data['hosting']) ? (int)$data['hosting'] : null;
            $this->cacheGeoInfo($ipAddress, $data);
            return $data;
        }

        return null;
    }

    private function cacheGeoInfo(string $ipAddress, array $data): void {
        $sql = "INSERT INTO ip_geolocation_cache (ip_address, country, region, city, lat, lon, isp, is_proxy, is_hosting) 
                VALUES (:ip, :country, :region, :city, :lat, :lon, :isp, :is_proxy, :is_hosting)
                ON DUPLICATE KEY UPDATE 
                country=VALUES(country), region=VALUES(region), city=VALUES(city), 
                lat=VALUES(lat), lon=VALUES(lon), isp=VALUES(isp),
                is_proxy=VALUES(is_proxy), is_hosting=VALUES(is_hosting)";
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            'ip' => $ipAddress,
            'country' => $data['country'] ?? null,
            'region' => $data['regionName'] ?? null,
            'city' => $data['city'] ?? null,
            'lat' => $data['lat'] ?? null,
            'lon' => $data['lon'] ?? null,
            'isp' => $data['isp'] ?? null,
            'is_proxy' => $data['is_proxy'] ?? null,
            'is_hosting' => $data['is_hosting'] ?? null
        ]);
    }
}