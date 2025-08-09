package config

type Config struct {
	DB     DBConfig     `json:"db"  yaml:"db"`
	Logger LoggerConfig `json:"logger"  yaml:"logger"`
	Server ServerConfig `json:"server"  yaml:"server"`
}

type DBConfig struct {
	Host     string `json:"host"  yaml:"host"`
	Port     uint   `json:"port"  yaml:"port"`
	Username string `json:"username"  yaml:"username"`
	Password string `json:"password"  yaml:"password"`
	Database string `json:"database"  yaml:"database"`
}

type ServerConfig struct {
	HttpPort          uint   `json:"httpPort"  yaml:"httpPort"`
	Secret            string `json:"secret"  yaml:"secret"`
	SslEnabled        bool   `json:"sslEnabled"  yaml:"sslEnabled"`
	Key               string `json:"key"  yaml:"key"`
	Cert              string `json:"cert"  yaml:"cert"`
	AuthExpMinute     uint   `json:"authExpMin"  yaml:"authExpMin"`
	AuthRefreshMinute uint   `json:"authExpRefreshMin"  yaml:"authExpRefreshMin"`
	// RateLimitMaxAttempt int    `json:"rate_limit_max_attempt"  yaml:"rate_limit_max_attempt"`
	// RatelimitTimePeriod int    `json:"ratelimit_time_period"  yaml:"ratelimit_time_period"`
}

type LoggerConfig struct {
	Level  string `json:"level"  yaml:"level"`
	Output string `json:"output"  yaml:"output"`
	Path   string `json:"path"  yaml:"path"`
}
