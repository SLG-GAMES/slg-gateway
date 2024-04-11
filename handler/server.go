package handler

import (
	"context"
	"errors"
	"fmt"
	"github/Gateway/common/config"
	"github/Gateway/common/logger"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

func Run() {
	router := SDKServerRoute()
	if router != nil {
		server := &http.Server{
			Addr:         ":" + config.GetServerConfig().HttpPort,
			Handler:      router,
			ReadTimeout:  time.Duration(config.GetServerConfig().ReadTimeout) * time.Second,
			WriteTimeout: time.Duration(config.GetServerConfig().WriteTimeout) * time.Second,
		}

		go func() {
			if err := server.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("listen: %v\n", err)
			}
		}()

		// Wait for interrupt signal to gracefully shutdown the server with
		// a timeout of 5 seconds.
		quit := make(chan os.Signal)
		// kill (no param) default send syscall.SIGTERM
		// kill -2 is syscall.SIGINT
		// kill -9 is syscall.SIGKILL but can't be caught, so don't need to add it
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit

		// The context is used to inform the server it has 5 seconds to finish
		// the request it is currently handling
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Logrus.WithFields(logrus.Fields{"ErrMsg": err.Error()}).Error("Server forced to shutdown")
		}

		logger.Logrus.Info("Server exiting")
	}
}
