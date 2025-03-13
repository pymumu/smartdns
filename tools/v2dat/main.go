package main

import (
	"github.com/urlesistiana/v2dat/cmd"
	_ "github.com/urlesistiana/v2dat/cmd/unpack"
)

func main() {
	_ = cmd.RootCmd.Execute()
}
