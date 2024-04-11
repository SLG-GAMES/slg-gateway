package config

import (
	"encoding/json"
	"fmt"
	"github/Gateway/common/logger"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/nacos-group/nacos-sdk-go/v2/clients"
	"github.com/nacos-group/nacos-sdk-go/v2/clients/config_client"
	"github.com/nacos-group/nacos-sdk-go/v2/common/constant"
	"github.com/nacos-group/nacos-sdk-go/v2/vo"
	"github.com/sirupsen/logrus"

	"github.com/spf13/viper"
	"github.com/urfave/cli"
)

const (
	LOGOUT_FILE   = "file"
	LOGOUT_STDOUT = "stdout"
)

type ServerConfig struct {
	RunMode      string
	HttpPort     string
	TargetURL    string
	ReadTimeout  int64
	WriteTimeout int64
	LogOut       string
}

type RedisConfig struct {
	UseCA        bool
	IP           string
	ConnPort     int64
	SSHPort      int64
	SSHAccount   string
	SSHKey       string
	Name         string
	Password     string
	Host         string
	DB           int64
	MinIdleConns int64
}

type MiddlewareLogConfig struct {
	VisitLogFile   string
	RecoverLogFile string
	SkipPath       []string
}

// struct decode must has tag
type Config struct {
	ServerConf        ServerConfig        `toml:"ServerConfig" mapstructure:"ServerConfig"`
	RedisConf         RedisConfig         `toml:"RedisConfig" mapstructure:"RedisConfig"`
	MiddlewareLogConf MiddlewareLogConfig `toml:"MiddlewareLogConfig" mapstructure:"MiddlewareLogConfig"`
}

type NacosConfig struct {
	ServerConfigs []constant.ServerConfig
	ClientConfig  constant.ClientConfig
	Group         string
}

var (
	configMutex  = sync.RWMutex{}
	config       Config
	nacos        NacosConfig
	configClient config_client.IConfigClient
	configViper  *viper.Viper
)

func watchConfig(c *viper.Viper) error {
	c.WatchConfig()
	c.OnConfigChange(func(e fsnotify.Event) {
		logger.Logrus.WithFields(logrus.Fields{"change": e.String()}).Info("config change and reload it")
		reloadConfig(c)
	})
	return nil
}

func LoadConf(configFilePath string) error {
	config = Config{}
	configMutex.Lock()
	defer configMutex.Unlock()

	configViper = viper.New()
	configViper.SetConfigName("config")
	configViper.AddConfigPath(configFilePath) //endwith "/"
	configViper.SetConfigType("yaml")

	if err := configViper.ReadInConfig(); err != nil {
		return err
	}
	if err := configViper.Unmarshal(&config); err != nil {
		return err
	}

	s, _ := json.MarshalIndent(config, "", "\t")
	fmt.Printf("Load config: %s", s)

	if err := watchConfig(configViper); err != nil {
		return err
	}
	return nil
}

func LoadFromNacos(c *viper.Viper) error {
	config = Config{}
	configMutex.Lock()
	defer configMutex.Unlock()

	if err := c.Unmarshal(&config); err != nil {
		return err
	}

	s, _ := json.MarshalIndent(config, "", "\t")
	fmt.Printf("Load config: %s", s)
	return nil
}

func reloadConfig(c *viper.Viper) {
	configMutex.Lock()
	defer configMutex.Unlock()

	if err := c.ReadInConfig(); err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err.Error()}).Error("config ReLoad failed")
	}

	if err := configViper.Unmarshal(&config); err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err.Error()}).Error("unmarshal config failed")
	}

	logger.Logrus.WithFields(logrus.Fields{"config": config}).Info("Config ReLoad Success")
}

func NewNacosConfig(cctx *cli.Context) (*viper.Viper, error) {
	configViper = viper.New()
	configViper.SetConfigType("yaml")

	log.Println("read config from nacos")

	group := cctx.String("Group")
	DataIds := cctx.String("DataIds")
	NacosAddrs := cctx.String("NacosAddrs")
	NacosAddrsList := strings.Split(NacosAddrs, ",")
	ServerConfigs := make([]constant.ServerConfig, len(NacosAddrsList))
	nacos.ServerConfigs = ServerConfigs
	nacos.Group = group
	for i, addr := range NacosAddrsList {
		addrArray := strings.Split(addr, ":")
		intNum, _ := strconv.Atoi(addrArray[1])
		nacos.ServerConfigs[i] = constant.ServerConfig{
			Scheme:      "http",
			ContextPath: "/nacos",
			IpAddr:      addrArray[0],
			Port:        uint64(intNum),
		}
	}
	NamespaceId := cctx.String("NamespaceId")
	NacosLogLevel := cctx.String("NacosLogLevel")
	nacos.ClientConfig = constant.ClientConfig{
		NamespaceId:         NamespaceId,
		LogLevel:            NacosLogLevel,
		NotLoadCacheAtStart: true,
		TimeoutMs:           30000,
	}
	for _, DataId := range strings.Split(DataIds, ",") {
		content, err := GetConfigByDataId(DataId)
		if err != nil {
			log.Fatal("Read remote config error:", err)
		}
		err = configViper.MergeConfig(strings.NewReader(content))
		if err != nil {
			log.Fatal("Read remote config error:", err)
		}
		err = configClient.ListenConfig(vo.ConfigParam{
			DataId: DataId,
			Group:  group,
			OnChange: func(namespace, group, dataId, data string) {
				configViper.MergeConfig(strings.NewReader(data))
				LoadFromNacos(configViper)
			},
		})
		if err != nil {
			log.Fatal("listen remote config error:", err)
		}
	}

	return configViper, nil
}

func GetConfigByDataId(DataId string) (string, error) {
	if configClient == nil {
		cli, err := clients.CreateConfigClient(
			map[string]interface{}{
				"clientConfig":  nacos.ClientConfig,
				"serverConfigs": nacos.ServerConfigs,
			},
		)
		if err != nil {
			return "", err
		}
		configClient = cli
	}
	content, err := configClient.GetConfig(vo.ConfigParam{
		DataId: DataId,
		Group:  nacos.Group})
	return content, err
}

func GetServerConfig() ServerConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return config.ServerConf
}

// check if logout equal file
func (c ServerConfig) LogOutFile() bool {
	return c.LogOut == LOGOUT_FILE
}

// check if logout equal stdout
func (c ServerConfig) LogOutStdout() bool {
	return c.LogOut == LOGOUT_STDOUT
}

func GetMiddlewareLogConfig() MiddlewareLogConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return config.MiddlewareLogConf
}

func GetRedisConfig() RedisConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return config.RedisConf
}
