# spiffe-jwt

A small sidecar/init container that obtains a JWT-SVID from the local SPIRE agent (SPIFFE Workload API) and writes it to a file for a workload to use. In daemon mode it refreshes the token before it expires and exposes an HTTP health endpoint.

Typically deployed alongside [simple-sidecar](https://github.com/CentML/simple-sidecar) and [ecr-anywhere](https://github.com/CentML/ecr-anywhere) in a SPIRE-based workload-identity setup.

## Configuration (environment variables / flags)

| Variable | Flag | Default | Description |
| --- | --- | --- | --- |
| `SPIFFE_AGENT_SOCKET` | `--spiffe-agent-socket` | required | Path of the SPIFFE agent Workload API socket |
| `JWT_AUDIENCE` | `--jwt-audience` | required | Audience claim of the requested JWT-SVID |
| `JWT_FILE_NAME` | `--jwt-file-name` | required | File to write the JWT-SVID to |
| `DAEMON_MODE` | `--daemon-mode` | `true` | Keep running and refresh the token; `false` fetches once and exits |
| `HEALTH_PORT` | `--health-port` | `8080` | Port for the health-check endpoint |
| `REFRESH_INTERVAL_OVERRIDE` | `--refresh-interval-override` | | Override the refresh interval (e.g. `30s`, `5m`) |

## Container image

Published to `ghcr.io/centml/spiffe-jwt` on each release tag. Third-party notices: [`THIRD-PARTY.txt`](THIRD-PARTY.txt).

## Contributing

This project is currently not accepting contributions.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
