<?php

namespace Google\Auth\Credentials;

use Google\Auth\Iam;
use Google\Auth\IAMSignerTrait;
use Google\Auth\SignBlobInterface;

class ImpersonatedServiceAccountCredentials extends UserRefreshCredentials implements SignBlobInterface
{
    use IAMSignerTrait;

    /**
     * @var Iam|null
     */
    private $iam;

    protected $serviceAccount;

    public function __construct(
        $scope,
        $jsonKey
    ) {
        if (is_string($jsonKey)) {
            if (!file_exists($jsonKey)) {
                throw new \InvalidArgumentException('file does not exist');
            }
            $json = file_get_contents($jsonKey);
            if (!$jsonKey = json_decode((string) $json, true)) {
                throw new \LogicException('invalid json for auth config');
            }
        }
        if (!array_key_exists('service_account_impersonation_url', $jsonKey)) {
            throw new \LogicException('json key is missing the service_account_impersonation_url field');
        }
        if (!array_key_exists('source_credentials', $jsonKey)) {
            throw new \LogicException('json key is missing the source_credentials field');
        }

        $this->serviceAccount = $this->getServiceAccountName($jsonKey['service_account_impersonation_url']);

        parent::__construct($scope, $jsonKey['source_credentials']);
    }

    /**
     * Helper function for extracting the Server Account Name from the URL saved in the account credentials file
     * @param $service_account_impersonation_url string URL from the 'service_account_impersonation_url' field
     * @return string Service account email or ID.
     */
    private function getServiceAccountName($service_account_impersonation_url)
    {
        $fields = explode("/", $service_account_impersonation_url);
        $last_field = end($fields);
        $splitter = explode(":", $last_field);
        return $splitter[0];
    }

    /**
     * Get the client name from the keyfile
     *
     * In this implementation, it will return the issuers email from the oauth token.
     *
     * @param callable|null $httpHandler not used by this credentials type.
     * @return string Token issuer email
     */
    public function getClientName(callable $httpHandler = null)
    {
        return $this->serviceAccount;
    }

}
