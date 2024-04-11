package main

import (
	"flag"

	"github/Gateway/common/config"
	"github/Gateway/common/logger"
	"github/Gateway/common/redis"
	"github/Gateway/handler"
	"log"
	"os"

	"github.com/urfave/cli"
)

func main() {
	local := []cli.Command{
		cli.Command{
			Name:  "run",
			Usage: "run --Group=test --DataIds=config_name1,config_name2 --NacosAddrs=127.0.0.1:8848,127.0.0.1:8849 --NamespaceId=test --NacosLogLevel=debug",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "Group", Usage: "--Group"},
				&cli.StringFlag{Name: "DataIds", Usage: "--DataIds"},
				&cli.StringFlag{Name: "NacosAddrs", Usage: "--NacosAddrs"},
				&cli.StringFlag{Name: "NamespaceId", Usage: "--NamespaceId"},
				&cli.StringFlag{Name: "NacosLogLevel", Usage: "--NacosLogLevel"},
			},
			Action: func(cctx *cli.Context) error {
				run(cctx)
				return nil
			},
		},
	}
	app := &cli.App{
		Name:  " go_sdk server",
		Usage: " go_sdk server",

		Commands: local,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func run(cctx *cli.Context) {
	env := os.Getenv("GO_ENV")
	configPath := flag.String("config_path", "./", "config file")
	logicLogFile := flag.String("logic_log_file", "./log/sdk.log", "logic log file")
	flag.Parse()

	//init logic logger
	logger.Init(*logicLogFile)

	if env != "local" {
		nacosConf, err := config.NewNacosConfig(cctx)
		if err != nil {
			log.Fatal("Read config error:", err)
		}
		//load config
		err = config.LoadFromNacos(nacosConf)
		if err != nil {
			log.Fatal("Load nacos config error:", err)
		}
	} else {
		err := config.LoadConf(*configPath)
		if err != nil {
			log.Fatal("load config failed:", err)
		}
	}
	serverConf := config.GetServerConfig()
	if serverConf.LogOutStdout() {
		logger.Logrus.Out = os.Stdout
	}

	err := redis.InitRedis()
	if err != nil {
		logger.Logrus.Error("init redis failed")
		return
	}

	//set log level
	logger.SetLogLevel(serverConf.RunMode)

	handler.Run()
}
