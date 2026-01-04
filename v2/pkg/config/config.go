package config

import "time"

// config file
type (
	Backend struct {
		BaseDN                    string
		Datastore                 string
		Insecure                  bool     // For LDAP and owncloud backend only
		Servers                   []string // For LDAP and owncloud backend only
		NameFormat                string   // e.g. cn, ou, uid, or a comma separated list of them
		NameFormatAsArray         []string // we will explode NameFormat on commas
		GroupFormat               string   // e.g. cn, ou, gid, or a comma separated list of them
		GroupFormatAsArray        []string // we will explode GroupFormat on commas
		SSHKeyAttr                string
		GroupWithSearchCapability string // For PamLinux backend only
	}

	Helper struct {
		Enabled   bool
		BaseDN    string
		Datastore string
	}

	LDAP struct {
		Listen string
	}

	API struct {
		Cert        string
		Enabled     bool
		Internals   bool
		Key         string
		Listen      string
		SecretToken string
		TLS         bool
	}

	Behaviors struct {
		IgnoreCapabilities    bool
		LimitFailedBinds      bool
		NumberOfFailedBinds   int
		PeriodOfFailedBinds   time.Duration
		BlockFailedBindsFor   time.Duration
		PruneSourceTableEvery time.Duration
		PruneSourcesOlderThan time.Duration
		LegacyVersion         int
	}

	Capability struct {
		Action string
		Object string
	}

	// UserAuthenticator authenticates a user via custom auth from a backend
	UserAuthenticator func(user *User, pw string) error
	User              struct {
		Name          string
		OtherGroups   []int
		PassSHA256    string
		PassBcrypt    string
		PassAppSHA256 []string
		PassAppBcrypt []string
		PassAppCustom UserAuthenticator `toml:"-"`
		PrimaryGroup  int
		Capabilities  []Capability
		SSHKeys       []string
		OTPSecret     string
		Yubikey       string
		Disabled      bool
		UnixID        int // TODO: remove after deprecating UnixID on User and Group
		UIDNumber     int
		Mail          string
		LoginShell    string
		GivenName     string
		SN            string
		Homedir       string
		CustomAttrs   map[string]interface{}
	}

	Group struct {
		Name          string
		UnixID        int // TODO: remove after deprecating UnixID on User and Group
		GIDNumber     int
		Capabilities  []Capability
		IncludeGroups []int
	}

	Config struct {
		API           API
		Backends      []Backend
		Helper        Helper
		Behaviors     Behaviors
		Debug         bool
		Syslog        bool
		StructuredLog bool
		LDAP          LDAP
		Groups        []Group
		Users         []User
		ConfigFile    string
	}
)
