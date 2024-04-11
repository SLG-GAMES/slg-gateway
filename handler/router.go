package handler

import (
	"encoding/json"
	"fmt"
	"github/Gateway/common/config"
	"github/Gateway/common/logger"
	"github/Gateway/common/redis"
	"io/ioutil"
	"strings"

	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Response struct {
	Code    int64       `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "*")
		c.Writer.Header().Set("Access-Control-Max-Age", "600")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func proxyHandler(c *gin.Context) {
	//check authorization
	//redis -> auth:address
	appID := c.Request.Header.Get("App-Id")
	userAddr := c.Request.Header.Get("Auth-Addr")
	authToken := c.Request.Header.Get("Authorization")

	if appID == "" || userAddr == "" || authToken == "" {
		logger.Logrus.WithFields(logrus.Fields{"App-Id": appID, "Auth-Addr": userAddr, "Authorization": authToken}).Error("SDK Gateway input parameter is empty")

		c.JSON(http.StatusBadRequest, &Response{
			Code:    http.StatusBadRequest,
			Message: "bad header",
		})
		return
	}

	//check authorization
	addrKey := fmt.Sprintf("auth:%s", strings.ToLower(userAddr))
	cacheToken, err := redis.GetString(addrKey)
	if err != nil {
		logger.Logrus.WithFields(logrus.Fields{"Cache-Key": addrKey, "ErrgMsg": err}).Error("SDK Gateway get cache token failed")

		c.JSON(http.StatusForbidden, &Response{
			Code:    http.StatusForbidden,
			Message: "bad token cache",
		})
		return
	}

	if cacheToken != authToken {
		logger.Logrus.WithFields(logrus.Fields{"Cache-token": cacheToken, "Auth-token": authToken}).Error("SDK Gateway bad auth token")

		c.JSON(http.StatusUnauthorized, &Response{
			Code:    http.StatusUnauthorized,
			Message: "unauthorization",
		})
		return
	}

	target := config.GetServerConfig().TargetURL
	proxyUrl, _ := url.Parse(target)

	proxy := httputil.NewSingleHostReverseProxy(proxyUrl)

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = "http"

		req.URL.Host = proxyUrl.Host
		req.Host = proxyUrl.Host
	}

	proxy.ModifyResponse = func(r *http.Response) error {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err.Error()}).Error("SDK Gateway get response body failed")

			return err
		}

		var result Response
		err = json.Unmarshal(b, &result)
		if err != nil {
			logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err.Error(), "RawData": string(b)}).Error("SDK Gateway get response body and unmarshal bytes failed")

			return err
		}

		logger.Logrus.WithFields(logrus.Fields{"Response": result}).Info("SDK Gateway get response data")

		c.JSON(http.StatusOK, &result)
		return nil
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

func SDKServerRoute() *gin.Engine {
	router := gin.New()

	middlewareLogConfig := config.GetMiddlewareLogConfig()
	recoverFile, err := os.OpenFile(middlewareLogConfig.RecoverLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil || recoverFile == nil {

		if err != nil {
			logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err.Error()}).Error("open recover log file failed")
		}
		if recoverFile == nil {
			logger.Logrus.Error("open recover log file failed:recoverFile is nil")
		}

		return nil
	}

	router.Use(ginLogger(middlewareLogConfig.VisitLogFile, middlewareLogConfig.SkipPath...), gin.RecoveryWithWriter(recoverFile))

	router.Use(CORSMiddleware())

	router.Any("/v1/*name", proxyHandler)
	router.Any("/marketplace/*name", proxyHandler)

	return router
}

// notLogged only use at programs start--router setting
func ginLogger(visitLogFile string, notLogged ...string) gin.HandlerFunc {

	visitLogInst := logrus.New()
	visitLogInst.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
	})
	visitLogInst.Out = &lumberjack.Logger{
		Filename:   visitLogFile,
		MaxSize:    500,
		MaxBackups: 10,
		MaxAge:     28,
		Compress:   true,
	}
	visitLogInst.SetLevel(logrus.DebugLevel)

	//skip path
	var skip map[string]struct{}

	if length := len(notLogged); length > 0 {
		skip = make(map[string]struct{}, length)

		for _, p := range notLogged {
			skip[p] = struct{}{}
		}
	}

	//visit log
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		if raw != "" {
			path = path + "?" + raw
		}

		start := time.Now()
		c.Next()
		stop := time.Since(start)
		latency := fmt.Sprintf("%d us", int(math.Ceil(float64(stop.Nanoseconds())/1000.0)))
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		clientUserAgent := c.Request.UserAgent()
		dataLength := c.Writer.Size()
		if dataLength < 0 {
			dataLength = 0
		}

		if _, ok := skip[path]; ok {
			return
		}

		entry := visitLogInst.WithFields(logrus.Fields{
			"statusCode": statusCode,
			"latency":    latency, // time to process
			"clientIP":   clientIP,
			"method":     c.Request.Method,
			"path":       path,
			"dataLength": dataLength,
			"userAgent":  clientUserAgent,
		})

		if len(c.Errors) > 0 {
			entry.Error(c.Errors.ByType(gin.ErrorTypePrivate).String())
		} else {
			if statusCode >= http.StatusInternalServerError {
				entry.Error()
			} else if statusCode >= http.StatusBadRequest {
				entry.Warn()
			} else {
				entry.Info()
			}
		}
	}
}
