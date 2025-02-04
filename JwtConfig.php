<?php

use \Firebase\JWT\JWT;

class JwtConfig
{
    private $secretKey;
    private $algorithm;
    private $issuer;
    private $audience;
    private $issuedAt;
    private $notBefore;
    private $expire;

    public function __construct($secretKey, $algorithm = 'HS256', $issuer = null, $audience = null, $issuedAt = null, $notBefore = null, $expire = null)
    {
        $this->secretKey = $secretKey;
        $this->algorithm = $algorithm;
        $this->issuer = $issuer;
        $this->audience = $audience;
        $this->issuedAt = $issuedAt ?? time();
        $this->notBefore = $notBefore ?? $this->issuedAt;
        $this->expire = $expire ?? ($this->issuedAt + 3600); // Default to 1 hour expiration
    }

    public function getSecretKey()
    {
        return $this->secretKey;
    }

    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    public function getIssuer()
    {
        return $this->issuer;
    }

    public function getAudience()
    {
        return $this->audience;
    }

    public function getIssuedAt()
    {
        return $this->issuedAt;
    }

    public function getNotBefore()
    {
        return $this->notBefore;
    }

    public function getExpire()
    {
        return $this->expire;
    }

    public function generateToken($payload = [])
    {
        $tokenPayload = array_merge($payload, [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'iat' => $this->issuedAt,
            'nbf' => $this->notBefore,
            'exp' => $this->expire
        ]);

        return JWT::encode($tokenPayload, $this->secretKey, $this->algorithm);
    }

    public function decodeToken($token)
    {
        return JWT::decode($token, $this->secretKey, [$this->algorithm]);
    }

    public function validateToken($token)
    {
        try {
            $decoded = $this->decodeToken($token);
            return (array) $decoded;
        } catch (Exception $e) {
            return false;
        }
    }
}
?>