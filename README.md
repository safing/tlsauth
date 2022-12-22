# TLS Client Cert Authentication Traefik Plugin

Traefik plugin to authenticate users based on the Common Name, DNS Names and Email Addresses of their TLS client certificate. Optionally add the username as a request header for the upstream service.

### Config

- Users
  - key/value map of CN/DNSName/EmailAddress of the TLS client certificate mapped to a username
  - only users in this map will be allowed, all others denied
- UsernameHeader
  - set to a header to include the username in upstream requests

```
type Config struct {
	Users          map[string]string
	UsernameHeader string
}
```
