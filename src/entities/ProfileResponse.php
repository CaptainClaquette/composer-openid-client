<?php

namespace hakuryo\OpenidClient\entities;

class ProfileResponse
{
    public string $sub;
    public string $service;
    public int $authTime;
    public array $attributes;
    public string $id;

    public string $clientId;

    public function __construct(\stdClass $data = null)
    {
        $this->sub = $data->sub;
        $this->service = $data->service;
        $this->authTime = $data->auth_time;
        $this->attributes = json_decode(json_encode($data->attributes), true);
        $this->id = $data->id;
        $this->clientId = $data->client_id;
    }
}
