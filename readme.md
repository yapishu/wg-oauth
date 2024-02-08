## WireGuard OAuth2 Gateway

This application is for managing a WireGuard VPN server with configurable firewall rules managed by OAuth2 authentication. Peers who connect to the server are blocked from LAN resources (with definable exceptions) until they perform authentication via 3rd party IdP. Once authenticated, the WG session is 'locked' to their connecting IP until the session expires or they reauthenticate. The authenticated peer is then given access to private LAN resources.

Not sure if this works in a container yet because of nftables kernel module stuff. Requires `wireguard` and `nftables` installed on host otherwise.

#### Variables

| Name | Description |
| --- | --- |
| `WG_COOKIE_KEY` | Crypto key for cookies |
| `NRLICENSE` | NewRelic API key |
| `DBPATH` | Local sqlite database path (match mount volume) |
| `WG_GROUP_MEMBER` | Azure security group UUID |
| `WG_AZURE_ID"` | Azure app ID |
| `WG_AZURE_SECRET` | Azure app secret |
| `WG_REDIRECT` | Full postauth redirect path |
| `LOCAL_SUBNET` | eg `192.168.0.0/16` |
| `FW_EXEMPTIONS` | default firewall allows, eg `192.168.0.3:53,192.168.0.4:80/tcp` |
| `ENVIRONMENT` | arbitrary env label |
| `HTTP_PORT` | web server port |
