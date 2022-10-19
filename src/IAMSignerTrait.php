<?php

namespace Google\Auth;

use Exception;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;

trait IAMSignerTrait
{
    /**
     * Sign a string using the default service account private key.
     *
     * This implementation uses IAM's signBlob API.
     *
     * @see https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/signBlob SignBlob
     *
     * @param string $stringToSign The string to sign.
     * @param bool $forceOpenSsl [optional] Does not apply to this credentials
     *        type.
     * @param string $accessToken The access token to use to sign the blob. If
     *        provided, saves a call to the metadata server for a new access
     *        token. **Defaults to** `null`.
     * @return string
     * @throws Exception
     */
    public function signBlob($stringToSign, $forceOpenSsl = false, $accessToken = null)
    {
        $httpHandler = HttpHandlerFactory::build(HttpClientCache::getHttpClient());

        // Providing a signer is useful for testing, but it's undocumented
        // because it's not something a user would generally need to do.
        $signer = $this->iam ?: new Iam($httpHandler);

        $email = $this->getClientName($httpHandler);

        if (is_null($accessToken)) {
            $previousToken = $this->getLastReceivedToken();
            $accessToken = $previousToken
                ? $previousToken['access_token']
                : $this->fetchAuthToken($httpHandler)['access_token'];
        }

        return $signer->signBlob($email, $accessToken, $stringToSign);
    }
}
