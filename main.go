package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	app, err := New(Config{
		MinimalTTL:             time.Hour,
		ChainPostfix:           "KVAS2_",
		TargetDNSServerAddress: "127.0.0.1:53",
		ListenPort:             7548,
	})
	if err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	appErrsChan := make(chan []error)
	go func() {
		errs := app.Listen(ctx)
		appErrsChan <- errs

	}()

	fmt.Println("Started service...")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case appErrs, _ := <-appErrsChan:
			for _, err := range appErrs {
				// TODO: Error log level
				log.Printf("failed to start application: %v", err)
			}
			return
		case <-c:
			fmt.Println("Graceful shutdown...")
			cancel()
		}
	}
}
