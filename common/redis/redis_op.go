package redis

import (
	"context"
	"errors"
	"fmt"

	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"github/Gateway/common/logger"
)

//script only return 1

func LuaRunWithValuefunc(script string, keys []string, args ...interface{}) (error, int64) {
	ctx := context.Background()
	luaScript := redis.NewScript(script)
	r, err := luaScript.Run(ctx, redisClient, keys, args).Result()
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis lua run failed")

		return err, 0
	}
	v, ok := r.(int64)
	if !ok {
		logger.Logrus.Error("redis lua run failed")

		return errors.New("Lua Exec Failed"), 0
	}

	return nil, v
}

func LuaRun(script string, keys []string, args ...interface{}) error {
	ctx := context.Background()
	luaScript := redis.NewScript(script)
	r, err := luaScript.Run(ctx, redisClient, keys, args).Result()
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis lua run failed")

		return err
	}

	v, ok := r.(int64)
	if !ok || v != 1 {
		logger.Logrus.Error("redis lua run failed")

		return errors.New("Lua Exec Failed")
	}

	return nil
}

func SetString(key string, value interface{}, ext int64) error {
	ctx := context.Background()
	defer func() {
		err := recover()
		if err != nil {
			logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis set string failed")
		}
	}()
	//ctx := context.Background()
	err := redisClient.Set(ctx, key, value, time.Duration(int64(time.Second)*ext)).Err()
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis set string failed")

		return err
	}
	return nil
}

func GetString(key string) (string, error) {
	ctx := context.Background()
	val, err := redisClient.Get(ctx, key).Result()
	if err == redis.Nil {
		errmsg := fmt.Sprintf("RedisError::Error:%s is not exist", key)

		return "", fmt.Errorf(errmsg)
	} else if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis get string failed")

		return "", err
	} else {
		return val, nil
	}
}

func GetStringAcceptable(key string) (string, error) {
	ctx := context.Background()
	val, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		} else {
			logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis get string failed")

		}
		return "", err
	} else {
		return val, nil
	}
}

func DeleteString(key string) error {
	ctx := context.Background()
	err := redisClient.Del(ctx, key).Err()
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis delete string failed")

		return err
	}
	return nil
}

func GetInt(key string) (int, error) {
	ctx := context.Background()
	val, err := redisClient.Get(ctx, key).Int()
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis get int failed")

		return 0, err
	} else {
		return val, nil
	}
}

func LPush(key string, exp int64, values ...interface{}) error {
	ctx := context.Background()
	err := redisClient.LPush(ctx, key, values...).Err()
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis lpush failed")

		return err
	}

	if exp > 0 {
		err = redisClient.Expire(ctx, key, time.Duration(int64(time.Second)*exp)).Err()
		if err != nil {
			logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis lpush failed")

			return err
		}
	}

	return nil
}

func LRange(key string) ([]string, error) {
	ctx := context.Background()
	r, err := redisClient.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis lrange failed")

		return []string{}, err
	}
	return r, nil

}

func LTrim(key string) error {
	ctx := context.Background()
	err := redisClient.LTrim(ctx, key, 1, 0).Err()
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis LTrim failed")

		return err
	}
	return nil
}

func Scan(regkey string) ([]string, error) {
	ctx := context.Background()
	iter := uint64(0)
	var keys []string

	for {
		var values []string
		var err error
		values, iter, err = redisClient.Scan(ctx, iter, regkey, 50).Result()
		if err != nil {
			logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis Scan failed")

			return nil, err
		}

		keys = append(keys, values...)

		if iter == 0 {
			break
		}
	}

	return keys, nil
}

func BatchDelete(keys []string) error {
	ctx := context.Background()
	pipe := redisClient.TxPipeline()
	defer pipe.Close()

	err := pipe.Del(ctx, keys...).Err()
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis BatchDelete failed")

		return fmt.Errorf("pipe del failed, %v", err)
	}
	_, err = pipe.Exec(ctx)
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err}).Error("redis BatchDelete failed")

		return fmt.Errorf("pipe exec failed, %v", err)
	}

	return nil
}

func ClearByKey(key string) error {
	keys, err := Scan(key)
	if err != nil {
		return fmt.Errorf("scan failed, %v", err)
	}

	if len(keys) == 0 {
		return nil
	}

	err = BatchDelete(keys)
	if err != nil {
		return fmt.Errorf("batch del failed, %v", err)
	}

	return nil
}

func GetAllValues(regkey string) ([]string, error) {
	keys, err := Scan(regkey)
	if err != nil {
		return nil, fmt.Errorf("scan failed, %v", err)
	}

	result := make([]string, 0)
	if len(keys) == 0 {
		return result, nil
	}

	values, err := redisClient.MGet(context.Background(), keys...).Result()
	if err != nil {
		return nil, err
	}

	for _, val := range values {
		value := val.(string)
		result = append(result, value)
	}

	return result, nil
}

func GetAllLength(regkey string) (int, error) {
	keys, err := Scan(regkey)
	if err != nil {
		return 0, fmt.Errorf("scan keys failed, %v", err)
	}

	if len(keys) == 0 {
		return 0, nil
	}

	values, err := redisClient.MGet(context.Background(), keys...).Result()
	if err != nil {
		return 0, fmt.Errorf("mget failed, %v", err)
	}

	return len(values), nil
}
