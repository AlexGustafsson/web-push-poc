# Web Push proxy PoC

This repository holds code to work with Web Push, as a client (using Mozilla's
autoconnect service), as a proxy for Mozilla's autoconnect service, as an
application server to send push messages or as a push service, handling
distribution of push messages.

The goal is to see if it's feasible to provide a service to replace browser
vendors' closed push services, making it possible to self-host infrastucture for
web push using services like Gotify. Either from a browser (essentially using a
browser extension to replace `PushManager` functionality) or via application
servers, only requiring them to support the standard Web Push format.

See also: <https://github.com/gotify/server/issues/765>

## autoconnect-proxy

A tool to act as a proxy between Firefox and autoconnect - Mozilla's WebSocket
service for Web Push.

```shell
# At least on macOS, Firefox uses the system's trust store for once
mkcert -install
mkcert localhost
```

In `about:config` in Firefox, set `dom.push.serverURL` to
`wss://localhost:8080`.

```shell
go run ./cmd/autoconnect-proxy/... | jq
```

Restart Firefox and use Web Push. All messages will be printed in the terminal.

## autoconnect-client

A tool to act as a client of autoconnect - Mozilla's WebSocket service for Web
Push. On start, connects to Mozilla's autoconnect and creates a subscription for
the provided application server. Prints the subscription object on start.

```shell
go run ./cmd/autoconnect-client/... <application server public key>
```

```json
{
  "endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABnsaKXD9TQQBnvUPMVtVh3ksOzMbYI4BtSZpTUeBElIPciCoTjFnHz3HcK8I2aUPY5h14LNnl_Ej8TflGDxfmQmXzdh3RUibjgvQTiXF5oPsoT3x91irhgdodwCoRzlrZYENahkFyIqb7A_S__Pdqq7eHMWCcHd-j8Yqiy-cf0htUkSDk",
  "expirationTime": null,
  "keys": {
    "auth": "Bbb0TH880GkTvuqV3JTseA",
    "p256dh": "BGFl7cU4de-Rwm8gI2Fxzbx8Q63WOfO71v6aAI1B1U3hYVFTHur3_rV9jBO73lCkb9eqqGKfqSpSOYHwjRt6EBc"
  }
}
```

Follow the instructions of the demo app to push messages to the client.

## application-server

A tool to act as a Web Push application server. On start, prints its public
application server key.

Use the public key with the autoconnect-client to create a subscription on
start, retrieve a subscription and then POST notifications via the application
server.

```shell
go run ./cmd/application-server/...
```

```text
2025/02/16 09:32:12 INFO Started application server applicationServerPublicKey=BGmGW79OZmRa2O6Z0nMgiFa1GplueAlQ_wJKIbO7EPuoNdTHPMxKL9nKJ3L2DCuR0MI_XhbJ0-7n1oFHYw-gvv8
```

The server exposes a push endpoint on `http://localhost:8081/api/v1/push` which
takes the following payload.

```jsonc
// payload.json
{
  // Subscription as defined by a client
  "subscription": {
    "endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABnsaKXD9TQQBnvUPMVtVh3ksOzMbYI4BtSZpTUeBElIPciCoTjFnHz3HcK8I2aUPY5h14LNnl_Ej8TflGDxfmQmXzdh3RUibjgvQTiXF5oPsoT3x91irhgdodwCoRzlrZYENahkFyIqb7A_S__Pdqq7eHMWCcHd-j8Yqiy-cf0htUkSDk",
    // Optional. Exists in Firefox, not Safari
    "expirationTime": null,
    "keys": {
      "auth": "Bbb0TH880GkTvuqV3JTseA",
      "p256dh": "BGFl7cU4de-Rwm8gI2Fxzbx8Q63WOfO71v6aAI1B1U3hYVFTHur3_rV9jBO73lCkb9eqqGKfqSpSOYHwjRt6EBc"
    }
  },
  "message": "Text message"
}
```

```shell
curl --verbose --data @test.json localhost:8081/api/v1/push
```

## agent

A PoC service that implements a user agent, letting an end-user create
subscriptions and manually provide them to an application server. The agent
server also acts as a push service, allowing application servers to push
messages directly  to the user agent/push service combo.

Start the agent.

```shell
go run ./cmd/agent/...
```

Start an application server.

```shell
go run ./cmd/application-server/...
```

Create a subscription.

```shell
curl --verbose localhost:8082/subscribe --data <application server public key>
```

```json
{
  "endpoint": "http://localhost:8082/ASqtcMsNphyJ_fssZiwwYBmU9QK-4INWlCliW0atFIe2CMJjCxomv2XNBW8YKWsxrdLHAf47w9bEelxFYHPq85ZR93OGtMOcXd6j0VNwOMUR8m8pa84SS6Ujg-dv_n9Gl6X1M8_1dRTaUvBZcj5NTJiVAeOSCcQhHEE9sD-bGgiChUveVE5BVVA233QiNg",
  "expirationTime": null,
  "keys": {
    "auth": "Ns56-ykn4ZXAhHMwRJvrzQ",
    "p256dh": "BECssUMYvdgbpHmQVukvRchqWk2x6rZAhQViSdnJlswn_9UWfosTIQ_p7isJQrbaejexTCP2BYvZNrk5ZFoR3KI"
  }
}
```

Then use the application server tool to push the message.

```shell
curl --verbose --data @payload.json localhost:8081/api/v1/push
```

## Code

The code is (mostly) split up into one package per RFC.

- `internal/aes128gcm` - Encrypted Content-Encoding for HTTP (RFC 8188)
- `internal/autoconnect` - Client for Mozilla's autoconnect Web Push service
- `internal/vapid` - Voluntary Application Server Identification (VAPID) for Web
  Push (RFC 8292) and the small subset of the JWT RFC that is required
  (RFC 7519, RFC 7518).
- `internal/webpush` - Generic Event Delivery Using HTTP Push (RFC 8030) and
  Message Encryption for Web Push (RFC 8291). Interface modeled after the web
  APIs (PushManager, PushSubscription)

## macOS/ios debugging

You can install the profile in `profile.mobileconfig` to log verbose logs from
`apsd`. Remember to uninstall it afterwards as it will log private fields.

## References

- https://github.com/mozilla-services/autopush-rs
- Generic Event Delivery Using HTTP Push - <https://datatracker.ietf.org/doc/html/rfc8030>
- Voluntary Application Server Identification for Web Push - <https://datatracker.ietf.org/doc/html/rfc8292>
- Web Push encryption - <https://datatracker.ietf.org/doc/html/draft-ietf-webpush-encryption-06>
- <https://web.dev/explore/notifications>
- <https://simple-push-demo.vercel.app/>
