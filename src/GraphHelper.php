<?php
namespace App;

use Microsoft\Graph\GraphServiceClient;
use Microsoft\Graph\Generated\AuditLogs\SignIns\SignInsRequestBuilderGetRequestConfiguration;
use Microsoft\Graph\Generated\AuditLogs\SignIns\SignInsRequestBuilderGetQueryParameters;
use Microsoft\Graph\Generated\Models\SignIn;
use Microsoft\Graph\Generated\Models\AuthenticationMethod;
use Microsoft\Graph\Generated\Models\User;
use Microsoft\Kiota\Authentication\Oauth\ClientCredentialContext;
use Microsoft\Graph\Generated\Users\UsersRequestBuilderGetRequestConfiguration;
use Microsoft\Graph\Generated\Users\UsersRequestBuilderGetQueryParameters;

class GraphHelper {
    private GraphServiceClient $graphServiceClient;

    public function __construct() {
        $tenantId = $_ENV['AZURE_TENANT_ID'];
        $clientId = $_ENV['AZURE_CLIENT_ID'];
        $clientSecret = $_ENV['AZURE_CLIENT_SECRET'];

        $tokenRequestContext = new ClientCredentialContext($tenantId, $clientId, $clientSecret);
        $scopes = ['https://graph.microsoft.com/.default'];
        
        $this->graphServiceClient = new GraphServiceClient($tokenRequestContext, $scopes);
    }

    /**
     * @return SignIn[]
     */
    public function getSignInLogs(): array {
        try {
            $requestConfiguration = new SignInsRequestBuilderGetRequestConfiguration();
            $queryParameters = new SignInsRequestBuilderGetQueryParameters();
            $queryParameters->top = 500;
            $queryParameters->orderby = ['createdDateTime desc'];
            $requestConfiguration->queryParameters = $queryParameters;
            
            $response = $this->graphServiceClient->auditLogs()->signIns()->get($requestConfiguration)->wait();
            
            return $response->getValue() ?? [];
        } catch (\Exception $e) {
            error_log("Graph API Error (getSignInLogs): " . $e->getMessage());
            return [];
        }
    }

    /**
     * @param string $userId
     * @return AuthenticationMethod[]
     */
    public function getAuthMethodsForUser(string $userId): array {
        try {
            $response = $this->graphServiceClient->users()->byUserId($userId)->authentication()->methods()->get()->wait();
            return $response->getValue() ?? [];
        } catch (\Exception $e) {
            error_log("Graph API Error (getAuthMethodsForUser for $userId): " . $e->getMessage());
            return [];
        }
    }

    /**
     * Gets all enabled, non-guest users in the tenant, handling pagination.
     * @return User[]
     */
    public function getAllUsers(): array {
        $allUsers = [];
        try {
            $requestConfiguration = new UsersRequestBuilderGetRequestConfiguration();
            $queryParameters = new UsersRequestBuilderGetQueryParameters();
            $queryParameters->filter = "accountEnabled eq true and userType eq 'Member'";
            $requestConfiguration->queryParameters = $queryParameters;

            $response = $this->graphServiceClient->users()->get($requestConfiguration)->wait();
            
            while ($response !== null) {
                $usersOnPage = $response->getValue();
                if ($usersOnPage) {
                    $allUsers = array_merge($allUsers, $usersOnPage);
                }
                
                $nextLink = $response->getOdataNextLink();
                if ($nextLink) {
                    $response = $this->graphServiceClient->users()->withUrl($nextLink)->get()->wait();
                } else {
                    $response = null; // No more pages
                }
            }
        } catch (\Exception $e) {
            error_log("Graph API Error (getAllUsers): " . $e->getMessage());
        }
        return $allUsers;
    }
}
