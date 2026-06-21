# ADR-0001: Docker-in-Docker Isolation for Analysis Containers

**Date:** 2026-06-21  
**Status:** Accepted  
**Context:** ClearCage threat analysis platform  
**Decision Maker:** Project lead  

## Problem

The backend needs to spawn ephemeral Docker containers for static/dynamic analysis (YARA, PE parsing, strings extraction, CAPEv2 sandboxing). Mounting the host's Docker socket (`/var/run/docker.sock`) grants root-equivalent access to the host — if the backend is compromised via a malicious file upload or FastAPI vulnerability, the attacker controls the entire host.

## Decision

Use **Docker-in-Docker (DinD)** instead of direct socket mount. The backend container runs its own Docker daemon inside its namespace. Analysis containers spawn within that isolated daemon, not on the host.

### Implementation

```yaml
services:
  api:
    build: ./backend
    privileged: true              # required for DinD daemon
    volumes:
      - yara-rules:/app/yara-rules:ro
      - samples:/app/storage
    environment:
      DOCKER_HOST: unix:///var/run/docker.sock  # internal DinD socket
```

Analysis containers inherit the same security guardrails:
- `AutoRemove: true` (ephemeral)
- Read-only volume mounts (`:ro`)
- Resource caps (`--memory=512m --cpus=1`)
- Network isolation (`--network none` for static phases, isolated bridge for CAPEv2)

## Consequences

| Positive | Negative |
|----------|----------|
| Blast radius contained to DinD namespace if backend compromised | Requires `privileged: true` on the API container |
| Analysis containers never touch host filesystem or network | Slightly higher overhead (DinD daemon inside container) |
| Host Docker daemon remains untouched by ClearCage | `docker compose ps` shows nested containers (debugging complexity) |

## Alternatives Considered

- **Direct socket mount** — simplest but unacceptable security risk for a malware analysis tool
- **Rootless Docker + proxy** — maximum control but highest complexity, overkill for local deployment

---

*Related: [CONTEXT.md](../CONTEXT.md), [architecture-research.md](../architecture-research.md)*
