package logger

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Logrus *logrus.Logger

func Init(logfile string) {
	logger := logrus.New()

	logger.SetReportCaller(true)

	logger.SetFormatter(&logrus.JSONFormatter{
		// PrettyPrint: true,
	})

	logger.Out = &lumberjack.Logger{
		Filename:   logfile,
		MaxSize:    500,
		MaxBackups: 10,
		MaxAge:     28,
		Compress:   true,
	}

	logger.SetLevel(logrus.DebugLevel)
	Logrus = logger
}

func SetLogLevel(runMode string) {
	modeLevel := logrus.InfoLevel

	switch runMode {
	case "debug":
		modeLevel = logrus.DebugLevel
	case "fatal":
		modeLevel = logrus.FatalLevel
	case "error":
		modeLevel = logrus.ErrorLevel
	case "warn":
		modeLevel = logrus.WarnLevel
	default:
		modeLevel = logrus.InfoLevel
	}

	Logrus.SetLevel(modeLevel)
}
