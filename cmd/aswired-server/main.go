package main

import (
	"context"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/httpapi"
	"github.com/AyanamiReiChan/ASWired-Server/internal/logfiles"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	if e := runCommand(os.Args[1:], os.Stdin, os.Stdout); e != nil {
		slog.Error("command failed", "error", e)
		os.Exit(1)
	}
}

var errDatabaseRestart = errors.New("database restart requested")

func run() error {
	for {
		if err := runController(); !errors.Is(err, errDatabaseRestart) {
			return err
		}
	}
}

func runController() error {
	cfg, e := config.Load()
	if e != nil {
		return e
	}
	logs, e := logfiles.Open(filepath.Join(cfg.DataDir, "logs"), 50<<20, 5)
	if e != nil {
		return e
	}
	defer logs.Close()
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.MultiWriter(os.Stderr, logs), nil)))
	defer slog.SetDefault(previousLogger)
	db, e := store.Open(store.Config{Driver: cfg.DatabaseDriver, DSN: cfg.DatabaseDSN})
	if e != nil {
		return e
	}
	defer db.Close()
	if cfg.DatabaseMaxOpen > 0 {
		db.DB().SetMaxOpenConns(cfg.DatabaseMaxOpen)
		db.DB().SetMaxIdleConns(cfg.DatabaseMaxIdle)
	}
	app, e := httpapi.New(cfg, db)
	if e != nil {
		return e
	}
	defer app.Close()
	migrationCtx, migrationCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	switched, migrationErr := app.ApplyDatabaseMigration(migrationCtx)
	migrationCancel()
	if migrationErr != nil {
		return migrationErr
	}
	if switched {
		return errDatabaseRestart
	}
	if e = app.EnableFileLogs(logs); e != nil {
		return e
	}
	defer app.CloseFileLogs()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app.Start(ctx)
	server := &http.Server{Addr: cfg.ListenAddr, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	slog.Info("ASWired controller started", "address", cfg.ListenAddr, "version", httpapi.Version)
	if initialized, e := db.Initialized(ctx); e == nil && !initialized {
		slog.Info("first setup requires the local setup-token file", "path", filepath.Join(cfg.DataDir, "setup-token"))
	}
	select {
	case e := <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		app.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		return server.Close()
	case <-app.RestartRequested():
		app.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			// Do not copy while an HTTP request may still be writing to SQLite.
			_ = server.Close()
			return errors.New("database restart drain timed out; restart the controller to resume migration")
		}
		return errDatabaseRestart
	}
}
