package config

import (
	"os"

	"sigs.k8s.io/yaml"
)

func ReadConfig(configPath string) (Config, error) {
	var config Config
	all, err := os.ReadFile(configPath)
	if err != nil {
		return config, err
	}

	return config, yaml.Unmarshal(all, &config)
}

func MustReadConfig(configPath string) Config {
	config, err := ReadConfig(configPath)
	if err != nil {
		panic(err)
	}
	return config
}
