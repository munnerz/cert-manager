package main

import (
	"log"
	"os"

	"github.com/spf13/cobra/doc"

	"github.com/jetstack/cert-manager/cmd/controller/app"
)

func main() {
	stopCh := make(chan struct{})
	cmd := app.NewCommandStartCertManagerController(os.Stdout, os.Stderr, stopCh)

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	err = doc.GenReSTTree(cmd, wd)
	if err != nil {
		log.Fatal(err)
	}
}
