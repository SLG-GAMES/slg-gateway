package redis

import (
	"context"
	"fmt"
	"github/Gateway/common/config"
	"github/Gateway/common/logger"
	"io/ioutil"
	"net"
	"sync"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
)

const Nil = redis.Nil

// one DB one client
var redisClient *redis.Client
var once sync.Once

func getSSHClient(hostip, user, keyfile string) (*ssh.Client, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"Error": err}).Error("error open keyfile")
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"Error": err}).Error("error parse keyfile")
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		Timeout:         time.Minute,
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	sshClient, err := ssh.Dial("tcp", hostip, config)
	if nil != err {
		logger.Logrus.WithFields(logrus.Fields{"Error": err}).Error("new ssh dial failed")
		return nil, err
	}

	return sshClient, nil
}

func InitRedis() error {
	redisClient = GetRedisInst()
	return nil
}

func GetRedisInst() *redis.Client {
	once.Do(func() {
		redisConfig := config.GetRedisConfig()
		var client *redis.Client
		if redisConfig.UseCA {
			hostip := fmt.Sprintf("%s:%d", redisConfig.IP, redisConfig.SSHPort)
			sshClient, err := getSSHClient(hostip, redisConfig.SSHAccount, redisConfig.SSHKey)
			if err != nil {
				panic(err)
			}
			options := &redis.Options{
				Addr:         redisConfig.Host,
				DB:           int(redisConfig.DB),
				MinIdleConns: int(redisConfig.MinIdleConns),
				DialTimeout:  time.Minute,
				Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return sshClient.Dial("tcp", redisConfig.Host)
				},
			}

			if redisConfig.Password != "" {
				options.Password = redisConfig.Password
			}
			client = redis.NewClient(options)
		} else {
			options := &redis.Options{
				Addr:         redisConfig.Host,
				Username:     redisConfig.Name,
				Password:     redisConfig.Password,
				DB:           int(redisConfig.DB),
				MinIdleConns: int(redisConfig.MinIdleConns),
			}
			if redisConfig.Password != "" {
				options.Password = redisConfig.Password
			}
			client = redis.NewClient(options)
		}

		redisClient = client
	})
	return redisClient
}
