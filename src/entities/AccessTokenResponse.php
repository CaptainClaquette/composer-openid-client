<?php

namespace hakuryo\OpenidClient\entities;

class AccessTokenResponse
{
    public $accessToken;
    public $tokenType;
    public $expiresIn;
    public $refreshToken;
    public $idToken;

    public function __construct(\stdClass $data)
    {
        $this->accessToken = $data->access_token ?? null;
        $this->tokenType = $data->token_type ?? null;
        $this->expiresIn = $data->expires_in ?? null;
        $this->refreshToken = $data->refresh_token ?? null;
        $this->idToken = $data->id_token ?? null;
    }
}
