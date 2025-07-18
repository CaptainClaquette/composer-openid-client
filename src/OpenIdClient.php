<?php

namespace hakuryo\OpenidClient;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use hakuryo\ConfigParser\ConfigParser;
use hakuryo\OpenidClient\entities\AccessTokenResponse;
use hakuryo\OpenidClient\entities\ProfileResponse;

class OpenIdClient
{
    public const MOD_BASIC = 1;
    public const MOD_POST = 2;
    public string $clientId;
    public string $clientSecret;
    public string $redirectUri;
    public string $scopes;
    public string $provider;
    public string $authorizeEndpoint;
    public string $accessTokenEndpoint;
    public string $logoutEndpoint;
    public string $userEndpoint;
    public $supportedScopes;

    public Client $httpClient;

    const MANDATORY_KEY = ["clientId", "clientSecret", "redirectUri", "scopes", "identityProviderUrl"];

    public function __construct($clientId, $clientSecret, $provider, $redirectUri, $scopes)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->provider = $provider;
        $this->redirectUri = $redirectUri;
        $this->scopes = $scopes;
        $this->httpClient = new Client();
    }

    public function getAuthorizationUrl(string $responseType = "code")
    {
        $params = array(
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => $responseType,
            'scope' => $this->scopes
        );
        return $this->authorizeEndpoint . '?' . http_build_query($params);
    }

    public function getAccessToken(string $code, int $mode = self::MOD_BASIC)
    {
        $params = [];
        $formParams = [
            'redirect_uri' => $this->redirectUri,
            "grant_type" => "authorization_code",
            "code" => $code,
            "scope" => $this->scopes,
        ];
        if ($mode === self::MOD_POST) {
            $formParams['client_id'] = $this->clientId;
            $formParams['client_secret'] = $this->clientSecret;
        }
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ];
        if ($mode === self::MOD_BASIC) {
            $params['auth'] = [$this->clientId, $this->clientSecret];
        }
        $params["form_params"] = $formParams;
        $params["headers"] = $headers;
        try {
            $request = new Request('POST', $this->accessTokenEndpoint, $params);
            $token_response = $this->httpClient->send($request, $params);
            $body = json_decode($token_response->getBody()->getContents());
            if (property_exists($body, 'access_token')) {
                return new AccessTokenResponse($body);
            }
        } catch (\Exception $ce) {
            error_log($ce->getMessage());
        }
        return null;
    }

    public function getUserInfo(AccessTokenResponse $accesTokenResponse)
    {
        $headers = [
            "cache-control" => "no-cache",
            "Accept" => "application/json",
            "Authorization" => "$accesTokenResponse->tokenType " . $accesTokenResponse->accessToken
        ];
        try {
            $me_response = $this->httpClient->get($this->userEndpoint, ["headers" => $headers]);
            return new ProfileResponse(json_decode($me_response->getBody()->getContents()));
        } catch (\Exception $ce) {
            error_log($ce->getMessage());
        }
        return null;
    }

    public static function fromFile($path, $section = null): OpenIdClient
    {
        $rawConf = ConfigParser::parse($path, $section, self::MANDATORY_KEY);
        $client = new OpenIdClient($rawConf->clientId, $rawConf->clientSecret, $rawConf->identityProviderUrl, $rawConf->redirectUri, $rawConf->scopes);
        $client->discoverEndpoints();
        return $client;

    }

    private function discoverEndpoints()
    {
        $wellKnownEndpoint = substr($this->provider, -1) === "/" ? "$this->provider.well-known" : "$this->provider/.well-known";
        $headers = [
            "cache-control" => "no-cache",
            "Accept" => "application/json"
        ];
        try {
            $response = $this->httpClient->get($wellKnownEndpoint, ["headers" => $headers]);
            if ($response->getStatusCode() === 200) {
                $data = json_decode($response->getBody()->getContents());
                if (property_exists($data, "authorization_endpoint")) {
                    $this->authorizeEndpoint = $data->authorization_endpoint;
                    $this->accessTokenEndpoint = $data->token_endpoint;
                    $this->userEndpoint = $data->userinfo_endpoint;
                    $this->logoutEndpoint = $data->end_session_endpoint;
                    $this->supportedScopes = json_decode(json_encode($data->scopes_supported), true);
                } else {
                    throw new \Exception("Can't retrieve authorization_endpoint key from $wellKnownEndpoint response was " . json_encode($response->getBody()->getContents()));
                }
            } else {
                throw new \Exception($response->getBody()->getContents());
            }
        } catch (\Exception $ce) {
            error_log($ce->getMessage());
        }
        return null;
    }
}
