idp-on-cloud-run
===
Sample IdP application on Cloud Run with Cloud KMS.

## Supported Key Algorithm

* 2048 bit RSA key PKCS#1 v1.5 padding - SHA256 Digest

## Deploy

```
gcloud beta run deploy \
  --platform=managed \
  --region=us-central1 \
  --allow-unauthenticated \
  --set-env-vars=KEY_RESOURCE_ID=${KMS_KEY_RESOURCE_NAME}
  --source .
  --service-account=${SERVICE_ACCOUNT}
  idp-on-cloud-run
```

## Endpoints

* `POST /id_token`

```
$ curl -X POST -H "Content-Type: application/json" --data '{"sub":"foo","aud":"bar"}' http://localhost:8080/id_token
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIifQ.eyJpYXQiOjE2MTk3NjQ1NDQsImV4cCI6MTYxOTc2NTQ0NCwic3ViIjoiZm9vIiwiYXVkIjoiYmFyIiwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODA4MCJ9.QwbatDR5vdQQCiqX3e_qCA1N3hufifE0cxmG2qOHl-RuizQtsfi1sLioR-aT8Rj9NzR8I9mJmgZPNwK1_pQ7iGyoSCtBO2iAgED1qrIkrioeyuAU52wigW4_RU9GGz1YP1zZjbC2yJ68el8_Lo25HWRZZfSwCdL2CQSbAnqbQmOmhJlUWZBsF8SSoFQotC0mg2nWFEqT8EHTjuB2RvNhgC5V7kFK8ONrNrYQIQze6x_i0hZ5HZnTTKFNQpB-1gdD9KpNevuFjFzvzH0CmlLmr-YWOQXMErjH6pfk3va4HkqBfraV1f6V5wV2DzlJJbSzsYyWhFie0huGzzY18cnzNg",
  "expires_in": 900
}
```

* `GET /tokeninfo`

```
$ curl http://localhost:8080/tokeninfo?id_token=$ID_TOKEN
{
  "active": true,
  "iat": 1619764544,
  "exp": 1619765444,
  "sub": "foo",
  "aud": "bar",
  "iss": "https://localhost:8080"
}
```

* `GET /certs`

```
$ curl http://localhost:8080/certs
{
  "keys": [
    {
      "kid": "2",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "mvynaw9v7JLu_9bK0ZpbhpypUFqyVutZOIP73daOqJl58_Q0js0-66kRHQLr0wFW95LfoxPPHC8bqJ2ofsjcZebp4C_Tg5sXiFIs2L-X30CrYz5A4hhXtTtYk1CGY5Qn1jq82f0RVPlUw4OhQudVakAvH6nBr8Prvr--NrCg24WPdXpWSBOTzzXUXIa49hoqcKaShZ77pbHbG9DoIKd-MkjdwvoC8jOz3cNjpLu1G6LBb5YV64R3yCbLeU0Q6Q5HG7YSqqKyVEPL9JjGrqGf_idoD_b7wABUKvqdNAS_MqiwJXItQiKUoMYnXrCfQfWzwy4Vj6zsq2g8xxBzVbNtDw",
      "e": "AQAB"
    }
  ]
}
```

* `GET /.well-known/openid-configuration`

```
$ curl http://localhost:8080/.well-known/openid-configuration
{
  "issuer": "https://localhost:8080",
  "jwks_uri": "https://localhost:8080/certs",
  "id_token_signing_alg_values_supported": [
    "RS256"
  ]
}
```