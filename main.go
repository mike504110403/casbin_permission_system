package main

import (
	"os"

	mlog "github.com/mike504110403/goutils/log"
)

func Init() {
	logConfig := mlog.Config{
		LogType: mlog.LogType(os.Getenv("Log_Type")),
		EnvMode: mlog.EnvMode(os.Getenv("Env_Mode")),
	}
	mlog.Init(logConfig)
}

func main() {
	Init()
	mlog.Info("modules test")
}
