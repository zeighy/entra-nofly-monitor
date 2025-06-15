<?php
namespace App;

use Microsoft\Graph\GraphServiceClient;
use Microsoft\Graph\Generated\AuditLogs\SignIns\SignInsRequestBuilderGetRequestConfiguration;
use Microsoft\Graph\Generated\Models\SignIn;
use Microsoft\Kiota\Authentication\Oauth\ClientCredentialContext;
use Microsoft\Graph\Generated\AuditLogs\SignIns\SignInsRequestBuilderGetQueryParameters;

class GraphHelper {
    private GraphServiceClient $graphServiceClient;

    public function __construct() {
        $tenantId = $_ENV['AZURE_TENANT_ID'];
        $clientId = $_ENV['AZURE_CLIENT_ID'];
        $clientSecret = $_ENV['AZURE_CLIENT_SECRET'];

        $tokenRequestContext = new ClientCredentialContext(
            $tenantId,
            $clientId,
            $clientSecret
        );
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

            // Pass the fully constructed configuration object to the get() method.
            $response = $this->graphServiceClient->auditLogs()->signIns()->get($requestConfiguration)->wait();
            
            return $response->getValue() ?? [];
        } catch (\Exception $e) {
            error_log("Graph API Error: " . $e->getMessage());
            return [];
        }
    }
}