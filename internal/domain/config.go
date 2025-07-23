package domain

import "time"

// CAConfig holds the configuration for the root CA.
type CAConfig struct {
	CA struct {
		Subject       SubjectConfig  `yaml:"subject"`
		Validity      Validity       `yaml:"validity"`
		KeyAlgorithm  KeyAlgorithm   `yaml:"key_algorithm"`
		HashAlgorithm HashAlgorithm  `yaml:"hash_algorithm"`
		Password      PasswordConfig `yaml:"password"`
	} `yaml:"ca"`
	Encryption EncryptionConfig `yaml:"encryption"`
}

// HostsConfig holds the configuration for all managed hosts.
type HostsConfig struct {
	Hosts map[string]HostConfig `yaml:"hosts"`
}

// HostConfig holds the configuration for a single host certificate.
type HostConfig struct {
	Subject          SubjectConfig `yaml:"subject"`
	AlternativeNames SANs          `yaml:"alternative_names"`
	Validity         Validity      `yaml:"validity"`
	KeyAlgorithm     KeyAlgorithm  `yaml:"key_algorithm"`
	HashAlgorithm    HashAlgorithm `yaml:"hash_algorithm"`
	Export           ExportConfig  `yaml:"export"`
	Deploy           DeployConfig  `yaml:"deploy"`
}

// SubjectConfig defines the fields for a certificate's subject.
type SubjectConfig struct {
	CommonName       string `yaml:"common_name"`
	Organization     string `yaml:"organization"`
	OrganizationUnit string `yaml:"organization_unit"`
	Country          string `yaml:"country"`
	State            string `yaml:"state"`
	Locality         string `yaml:"locality"`
	Email            string `yaml:"email"`
}

// Validity defines the duration for which a certificate is valid.
type Validity struct {
	Years int `yaml:"years"`
	Days  int `yaml:"days"`
}

func (v Validity) ToDuration() time.Duration {
	return time.Duration(v.Years)*365*24*time.Hour + time.Duration(v.Days)*24*time.Hour
}

// PasswordConfig defines how the master password is managed.
type PasswordConfig struct {
	MinLength int    `yaml:"min_length"`
	File      string `yaml:"file"`
	EnvVar    string `yaml:"env_var"`
}

// SANs holds the Subject Alternative Names.
type SANs struct {
	DNS   []string `yaml:"dns"`
	IP    []string `yaml:"ip"`
	Email []string `yaml:"email"`
	URI   []string `yaml:"uri"`
}

// ExportConfig defines paths for exporting generated files.
type ExportConfig struct {
	Cert  string `yaml:"cert"`
	Chain string `yaml:"chain"`
}

// DeployConfig defines the command(s) to run after issuance.
type DeployConfig struct {
	Commands []string `yaml:"commands"`
}

// EncryptionConfig defines how private keys are encrypted.
type EncryptionConfig struct {
	Provider string         `yaml:"provider"`
	Password PasswordConfig `yaml:"password"`
	SSH      SSHConfig      `yaml:"ssh"`
}

// SSHConfig defines SSH key-based encryption configuration.
type SSHConfig struct {
	IdentityFile string   `yaml:"identity_file"`
	Recipients   []string `yaml:"recipients"`
}
