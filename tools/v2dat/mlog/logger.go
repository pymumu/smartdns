package mlog

import "go.uber.org/zap"

var logger = mustInitLogger()

func mustInitLogger() *zap.Logger {
	l, err := zap.NewDevelopment(zap.WithCaller(false))
	if err != nil {
		panic("failed to init mlog:" + err.Error())
	}
	return l
}

func L() *zap.Logger {
	return logger
}
