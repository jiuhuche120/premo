package ethereum

import (
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

const (
	configName = "ethereum.toml"
)

type Config struct {
	Ether Ether `toml:"ether" json:"ether"`
}

type Ether struct {
	Addr            string `toml:"addr" json:"addr"`
	Name            string `toml:"name" json:"name"`
	ContractAddress string `mapstructure:"contract_address" json:"contract_address"`
	AbiPath         string `mapstructure:"abi_path" json:"abi_path"`
	KeyPath         string `mapstructure:"key_path" json:"key_path"`
	Password        string `toml:"password" json:"password"`
}

func defaultConfig() *Config {
	return &Config{
		Ether: Ether{
			Addr:            "https://mainnet.infura.io",
			Name:            "Ethereum",
			ContractAddress: "0xD3880ea40670eD51C3e3C0ea089fDbDc9e3FBBb4",
			AbiPath:         "broker.abi",
			KeyPath:         "account.key",
			Password:        "",
		},
	}
}

func UnmarshalConfig(configRoot string) (*Config, error) {
	viper.SetConfigFile(filepath.Join(configRoot, configName))
	viper.SetConfigType("toml")
	viper.AutomaticEnv()
	viper.SetEnvPrefix("ETHER")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	config := defaultConfig()

	if err := viper.Unmarshal(config); err != nil {
		return nil, err
	}

	return config, nil
}
