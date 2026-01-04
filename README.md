# GLAuth - Embedded LDAP Server for Go Testing

A lightweight fork of [glauth/glauth](https://github.com/glauth/glauth) designed specifically for Go integration and e2e testing. Start an LDAP server directly in your test code without Docker, Podman, or external dependencies.

## Purpose

This fork strips away production features to provide a minimal, embeddable LDAP server for testing LDAP authentication in Go applications. No containers required—just import and start the server in your test code.

## What's Included

- Embedded LDAP server for Go tests
- Config-based user/group management
- Standard LDAP bind/search operations
- SHA256 and Bcrypt password hashing
- SSH key authentication
- Capabilities system for search access control
- Minimal dependencies (uses slog, not zerolog)

## What's Removed

- Plugin system
- Database backends (MySQL, PostgreSQL, SQLite, PAM)
- OwnCloud support
- Hot config reload
- Statistics/metrics
- Web UI
- REST API
- Two-factor authentication (OTP/YubiKey)
- Distributed tracing

## Installation

```bash
go get github.com/franchb/glauth/v2
```

## Quick Start

### Minimal In-Memory Config

```go
package main

import (
    "log/slog"
    "github.com/franchb/glauth/v2/pkg/server"
    "github.com/franchb/glauth/v2/pkg/config"
)

func main() {
    cfg := &config.Config{
        LDAP: config.LDAP{Listen: "localhost:3893"},
        Backends: []config.Backend{{
            Datastore: "config",
            BaseDN:    "dc=example,dc=com",
        }},
        Users: []config.User{{
            Name:         "testuser",
            UIDNumber:    5001,
            PrimaryGroup: 5501,
            PassSHA256:   "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a", // dogood
        }},
        Groups: []config.Group{{
            Name:     "testgroup",
            GIDNumber: 5501,
        }},
    }

    s, _ := server.NewServer(
        server.Logger(slog.Default()),
        server.Config(cfg),
    )
    go s.ListenAndServe()
    // Your test code here...
    s.Shutdown()
}
```

### Test Helper Pattern

```go
package mytest

import (
    "testing"
    "time"
    "log/slog"
    "github.com/franchb/glauth/v2/pkg/server"
    "github.com/franchb/glauth/v2/pkg/config"
)

func setupTestLDAP(t *testing.T) (*server.LdapSvc, func()) {
    cfg := &config.Config{
        LDAP: config.LDAP{Listen: "localhost:3893"},
        Backends: []config.Backend{{
            Datastore: "config",
            BaseDN:    "dc=test,dc=com",
        }},
        Users: []config.User{{
            Name:         "alice",
            UIDNumber:    1001,
            PrimaryGroup: 100,
            PassSHA256:   "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a", // dogood
        }},
        Groups: []config.Group{{
            Name:     "users",
            GIDNumber: 100,
        }},
    }

    s, err := server.NewServer(
        server.Logger(slog.Default()),
        server.Config(cfg),
    )
    if err != nil {
        t.Fatal(err)
    }

    go s.ListenAndServe()
    time.Sleep(100 * time.Millisecond) // Wait for server to start

    return s, func() { s.Shutdown() }
}

// Usage in test:
func TestLDAPAuth(t *testing.T) {
    _, cleanup := setupTestLDAP(t)
    defer cleanup()

    // Your LDAP test code here...
}
```

### TOML Config File

Create a `config.toml`:

```toml
[ldap]
listen = "localhost:3893"

[backend]
datastore = "config"
baseDN = "dc=example,dc=com"

[[users]]
name = "alice"
uidnumber = 1001
primarygroup = 100
passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood

[[groups]]
name = "users"
gidnumber = 100
```

Load it in Go:

```go
package main

import (
    "log/slog"
    "os"
    "github.com/franchb/glauth/v2/internal/toml"
    "github.com/franchb/glauth/v2/pkg/server"
)

func main() {
    data, _ := os.ReadFile("config.toml")
    cfg, _ := toml.NewConfig(string(data))

    s, _ := server.NewServer(
        server.Logger(slog.Default()),
        server.Config(cfg),
    )
    go s.ListenAndServe()
    // Test code...
    s.Shutdown()
}
```

### With Capabilities (Access Control)

```go
cfg := &config.Config{
    Backends: []config.Backend{{
        Datastore: "config",
        BaseDN:    "dc=example,dc=com",
    }},
    Users: []config.User{{
        Name:         "serviceuser",
        UIDNumber:    5003,
        PrimaryGroup: 5502,
        PassSHA256:   "652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0", # mysecret
        Capabilities: []config.Capability{{
            Action: "search",
            Object: "*",
        }},
    }},
    Groups: []config.Group{
        {Name: "admins", GIDNumber: 5501},
        {Name: "svcaccts", GIDNumber: 5502},
    },
}
```

## Configuration Reference

### Top-level Settings

| Field | Description |
|-------|-------------|
| `[ldap].listen` | Server listen address (e.g., `localhost:3893`) |
| `[backend].datastore` | Must be `"config"` for embedded use |
| `[backend].baseDN` | Base distinguished name (e.g., `dc=example,dc=com`) |

### User Fields

| Field | Description |
|-------|-------------|
| `name` | Username (login name) |
| `uidnumber` | POSIX UID |
| `primarygroup` | Primary group GID |
| `othergroups` | Additional group memberships |
| `passsha256` | SHA256 password hash |
| `passbcrypt` | Bcrypt password hash |
| `passappsha256` | Application-specific passwords |
| `sshkeys` | SSH public keys |
| `mail` | Email address |
| `givenname` | First name |
| `sn` | Last name |
| `loginshell` | POSIX login shell |
| `homedir` | POSIX home directory |
| `capabilities` | Search permissions |
| `disabled` | Disable the account |

### Group Fields

| Field | Description |
|-------|-------------|
| `name` | Group name |
| `gidnumber` | POSIX GID |
| `includegroups` | Include members from other groups |
| `capabilities` | Search permissions |

### Capabilities

Capabilities control what users can search for:

```toml
[[users]]
name = "alice"
uidnumber = 1001
primarygroup = 100
passsha256 = "..."

  [[users.capabilities]]
  action = "search"
  object = "ou=admins,dc=example,dc=com"
```

- `action`: Currently only `"search"` is supported
- `object`: LDAP DN pattern to allow searching

## Password Hash Generation

```bash
# SHA256
echo -n "mypassword" | openssl dgst -sha256

# Bcrypt (requires bcrypt-cli or similar)
bcrypt-cli "mypassword"
```

Example SHA256 for "dogood":
```
6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a
```

## Testing with ldapsearch

Verify your LDAP server is running:

```bash
# Search for a specific user
ldapsearch -LLL -H ldap://localhost:3893 \
  -D cn=testuser,ou=users,dc=example,dc=com -w dogood \
  -x -bdc=example,dc=com cn=testuser

# List all users (posixAccount)
ldapsearch -LLL -H ldap://localhost:3893 \
  -D cn=testuser,ou=users,dc=example,dc=com -w dogood \
  -x -bdc=example,dc=com objectClass=posixAccount

# List all groups
ldapsearch -LLL -H ldap://localhost:3893 \
  -D cn=testuser,ou=users,dc=example,dc=com -w dogood \
  -x -bdc=example,dc=com objectClass=posixGroup
```

## Running Tests

```bash
# Unit tests
go test ./pkg/... ./internal/...

# Integration tests (requires ldap-utils)
cd v2 && make test
```

## Dependencies

```
github.com/BurntSushi/toml
github.com/glauth/ldap
golang.org/x/crypto
```

Uses Go's built-in `log/slog` for logging—no external logging dependencies.

## License

MIT License - see LICENSE file for details.

## Credits

- [glauth/glauth](https://github.com/glauth/glauth) - Original project
- [glauth/ldap](https://github.com/glauth/ldap) - LDAP library
