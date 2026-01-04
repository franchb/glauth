package toml

import (
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/glauth/glauth/v2/pkg/config"
)

var (
	log slog.Logger
)

func SetLogger(logger slog.Logger) {
	log = logger
}

type Config struct {
	Users []toml.Primitive
}

type User struct {
	Name             string
	CustomAttributes []toml.Primitive
}

// NewConfig reads the cli flags and config file
func NewConfig(data string) (*config.Config, error) {
	// Parse config-file into config{} struct
	cfg, err := parseConfig(data)
	if err != nil {
		return nil, err
	}

	cfg, err = validateConfig(cfg)
	if err != nil {
		return nil, err
	}

	// TODO @shipperizer reinstate this
	// // Before greenlighting new config entirely, lets make sure the yubiauth works - in case they changed

	return cfg, nil
}

func parseConfig(data string) (*config.Config, error) {
	cfg := new(config.Config)
	// setup defaults

	if _, err := toml.Decode(data, cfg); err != nil {
		return cfg, err
	}

	usersCustomAttributes(data, cfg)

	// Patch with default values where not specified
	for i := range cfg.Backends {
		if cfg.Backends[i].NameFormat == "" {
			cfg.Backends[i].NameFormat = "cn,uid"
		}
		cfg.Backends[i].NameFormatAsArray = strings.Split(cfg.Backends[i].NameFormat, ",")
		if cfg.Backends[i].GroupFormat == "" {
			cfg.Backends[i].GroupFormat = "ou,cn"
		}
		cfg.Backends[i].GroupFormatAsArray = strings.Split(cfg.Backends[i].GroupFormat, ",")
		if cfg.Backends[i].SSHKeyAttr == "" {
			cfg.Backends[i].SSHKeyAttr = "sshPublicKey"
		}
	}
	//

	return cfg, nil
}

// usersCustomAttributes changes config passed in by adding extra information coming from the custom attributes
func usersCustomAttributes(data string, config *config.Config) {
	// TODO @shipperizer deal with multiple files like in line #126
	c := new(Config)

	md, err := toml.Decode(data, c)

	if err != nil {
		log.Error("issues parsing users...keep going", "err", err)
		return
	}

	for _, u := range c.Users {
		user := new(User)
		md.PrimitiveDecode(u, user)

		if user.CustomAttributes == nil {
			continue
		}

		for idx, cUser := range config.Users {
			if cUser.Name != user.Name {
				continue
			}

			x := make(map[string]interface{})

			for _, attribute := range user.CustomAttributes {
				_ = md.PrimitiveDecode(attribute, x)

				for k, v := range x {

					if config.Users[idx].CustomAttrs == nil {
						config.Users[idx].CustomAttrs = make(map[string]interface{})
					}

					config.Users[idx].CustomAttrs[k] = v

				}
			}
		}
	}
}

func mergeConfigs(config1 interface{}, config2 interface{}) error {
	var merger func(int, string, interface{}, interface{}) error
	merger = func(depth int, keyName string, cfg1 interface{}, cfg2 interface{}) error {
		//fmt.Println(strings.Repeat("    ", depth), "Handling element: ", keyName, " for: ", cfg2)
		switch element2 := cfg2.(type) {
		case map[string]interface{}:
			//fmt.Println(strings.Repeat("     ", depth), " - A map")
			element2, ok := cfg2.(map[string]interface{})
			if !ok {
				return fmt.Errorf("config source: %s is not a map", keyName)
			}
			element1, ok := cfg1.(*map[string]interface{})
			if !ok {
				return fmt.Errorf("config dest: %s is not a map", keyName)
			}
			for k, _ := range element2 {
				//fmt.Println(strings.Repeat("     ", depth), "  - key: ", k)
				_, ok := (*element1)[k]
				if !ok {
					(*element1)[k] = element2[k]
				} else {
					//fmt.Println(strings.Repeat("     ", depth), "  - merging: ", element2[k])
					asanarrayptr, ok := (*element1)[k].([]map[string]interface{})
					if ok {
						if err := merger(depth+1, k, &asanarrayptr, element2[k]); err != nil {
							return err
						}
						(*element1)[k] = asanarrayptr
					} else {
						asamapptr, ok := (*element1)[k].(map[string]interface{})
						if ok {
							if err := merger(depth+1, k, &asamapptr, element2[k]); err != nil {
								return err
							}
							(*element1)[k] = asamapptr
						} else {
							return fmt.Errorf("config dest: %s does not make a valid map/array ptr", keyName)
						}
					}
				}
			}
		case []map[string]interface{}:
			//fmt.Println(strings.Repeat("     ", depth), " - An array")
			element2, ok := cfg2.([]map[string]interface{})
			if !ok {
				return fmt.Errorf("config source: %s is not a map array", keyName)
			}
			//fmt.Println(strings.Repeat("     ", depth), "  - element2: ", element2)
			element1, ok := cfg1.(*[]map[string]interface{})
			if !ok {
				return fmt.Errorf("config dest: %s is not a map array", keyName)
			}
			//fmt.Println(strings.Repeat("     ", depth), "  - element1: ", element1)
			for index, _ := range element2 {
				*element1 = append(*element1, element2[index])
			}
		case string:
			//fmt.Println(strings.Repeat("     ", depth), " - A string")
			element2, ok := cfg2.(string)
			if !ok {
				return fmt.Errorf("config: %s is not a string", keyName)
			}
		case bool:
			//fmt.Println(strings.Repeat("     ", depth), " - A boolean")
			element2, ok := cfg2.(bool)
			if !ok {
				return fmt.Errorf("config: %s is not a boolean value", keyName)
			}
		case float64:
			//fmt.Println(strings.Repeat("     ", depth), " - A float64")
			element2, ok := cfg2.(float64)
			if !ok {
				return fmt.Errorf("config: %s is not a float64 value", keyName)
			}
		case nil:
			//fmt.Println(strings.Repeat("     ", depth), " - Nil")
		default:
			log.Info("Unknown element type found in configuration file. Ignoring.", "type", reflect.TypeOf(element2).String())
		}
		return nil
	}

	err := merger(0, "TOP", config1, config2)
	if err != nil {
		return err
	}
	return nil
}

func validateConfig(cfg *config.Config) (*config.Config, error) {

	// LDAP enabled - verify listen
	if len(cfg.LDAP.Listen) == 0 {
		return cfg, fmt.Errorf("no LDAP bind address was specified: please disable LDAP or use the 'listen' option")
	}

	//spew.Dump(cfg)
	for i := range cfg.Backends {
		switch cfg.Backends[i].Datastore {
		case "":
			cfg.Backends[i].Datastore = "config"
		case "config":
		case "ldap":
		case "plugin":
		default:
			return cfg, fmt.Errorf("invalid backend %s - must be 'config', 'ldap', 'owncloud', 'plugin' or 'embed", cfg.Backends[i].Datastore)
		}
	}

	// TODO: remove after deprecating UnixID on User and Group
	for _, user := range cfg.Users {
		if user.UnixID != 0 {
			user.UIDNumber = user.UnixID
			log.Info(fmt.Sprintf("User '%s': 'unixid' is deprecated - please move to 'uidnumber' as per documentation", user.Name))
		}
	}
	for _, group := range cfg.Groups {
		if group.UnixID != 0 {
			group.GIDNumber = group.UnixID
			log.Info(fmt.Sprintf("Group '%s': 'unixid' is deprecated - please move to 'gidnumber' as per documentation", group.Name))
		}
	}

	return cfg, nil
}
