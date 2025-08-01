package domain

// CAConfig holds the configuration for the root CA.
type CAConfig struct {
	CA struct {
		Subject       SubjectConfig    `yaml:"subject"`
		Validity      Validity         `yaml:"validity"`
		KeyAlgorithm  KeyAlgorithm     `yaml:"key_algorithm"`
		HashAlgorithm HashAlgorithm    `yaml:"hash_algorithm"`
		Extensions    ExtensionsConfig `yaml:"extensions,omitempty"`
	} `yaml:"ca"`
	Encryption EncryptionConfig `yaml:"encryption"`
	Display    DisplayConfig    `yaml:"display"`
}

// HostsConfig holds the configuration for all managed hosts.
type HostsConfig struct {
	Hosts map[string]HostConfig `yaml:"hosts"`
}

// HostConfig holds the configuration for a single host certificate.
type HostConfig struct {
	Subject          SubjectConfig    `yaml:"subject"`
	AlternativeNames SANs             `yaml:"alternative_names"`
	Validity         Validity         `yaml:"validity"`
	KeyAlgorithm     KeyAlgorithm     `yaml:"key_algorithm"`
	HashAlgorithm    HashAlgorithm    `yaml:"hash_algorithm"`
	Extensions       ExtensionsConfig `yaml:"extensions,omitempty"`
	Export           ExportConfig     `yaml:"export"`
	Deploy           DeployConfig     `yaml:"deploy"`
	Encryption       *HostEncryption  `yaml:"encryption,omitempty"`
}

// SubjectConfig defines the fields for a certificate's subject.
type SubjectConfig struct {
	CommonName         string `yaml:"common_name"`
	Organization       string `yaml:"organization"`
	OrganizationalUnit string `yaml:"organizational_unit"`
	Country            string `yaml:"country"`
	State              string `yaml:"state"`
	Locality           string `yaml:"locality"`
	Email              string `yaml:"email"`
}

// Validity defines the duration for which a certificate is valid.
type Validity struct {
	Years  int `yaml:"years"`
	Months int `yaml:"months"`
	Days   int `yaml:"days"`
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
	Cert         string `yaml:"cert"`
	Chain        string `yaml:"chain"`
	KeyEncrypted string `yaml:"key_encrypted"`
}

// DeployConfig defines the command to run after issuance.
type DeployConfig struct {
	Command string `yaml:"command"`
}

// EncryptionConfig defines how private keys are encrypted.
type EncryptionConfig struct {
	Provider string         `yaml:"provider"`
	Password PasswordConfig `yaml:"password"`
	SSH      SSHConfig      `yaml:"ssh"`
	Plugin   PluginConfig   `yaml:"plugin"`
}

// SSHConfig defines SSH key-based encryption configuration.
type SSHConfig struct {
	IdentityFile string   `yaml:"identity_file"`
	Recipients   []string `yaml:"recipients"`
}

// PluginConfig defines age plugin-based encryption configuration.
// Works with any age-plugin-* binary (secure-enclave, yubikey, tpm, etc.)
type PluginConfig struct {
	IdentityFile string   `yaml:"identity_file"` // Path to age identity file
	Recipients   []string `yaml:"recipients"`    // Plugin recipient strings
}

// DisplayConfig defines how certificate status is displayed.
type DisplayConfig struct {
	Warnings WarningThresholds `yaml:"warnings"`
}

// WarningThresholds defines the day thresholds for certificate expiry warnings.
type WarningThresholds struct {
	Critical int `yaml:"critical"` // Days remaining to show red warning (default: 7)
	Warning  int `yaml:"warning"`  // Days remaining to show yellow warning (default: 30)
}

// GetCriticalDays returns the critical threshold with a default of 7 days.
func (w WarningThresholds) GetCriticalDays() int {
	if w.Critical <= 0 {
		return 7
	}
	return w.Critical
}

// GetWarningDays returns the warning threshold with a default of 30 days.
func (w WarningThresholds) GetWarningDays() int {
	if w.Warning <= 0 {
		return 30
	}
	return w.Warning
}

// GetWarningThresholds returns the warning thresholds from CAConfig with defaults applied.
func (c *CAConfig) GetWarningThresholds() WarningThresholds {
	return c.Display.Warnings
}

// HostEncryption defines additional encryption recipients for a specific host.
type HostEncryption struct {
	AdditionalRecipients []string `yaml:"additional_recipients,omitempty"`
}
