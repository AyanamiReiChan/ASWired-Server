package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/httpapi"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

var buildVersion = "development"
var buildCommit = "unknown"

func runCommand(args []string, input io.Reader, output io.Writer) error {
	if buildVersion != "development" && buildVersion != "" {
		httpapi.Version = buildVersion
	}
	if len(args) == 0 {
		return run()
	}
	switch args[0] {
	case "serve":
		if len(args) != 1 {
			return errors.New("serve uses ASWIRED_* environment configuration")
		}
		return run()
	case "version":
		fmt.Fprintf(output, "ASWired Server %s (API %s, commit %s, %s/%s)\n", buildVersion, httpapi.Version, buildCommit, runtime.GOOS, runtime.GOARCH)
		return nil
	case "reset-password":
		return resetPasswordCommand(args[1:], input, output)
	case "upgrade":
		return upgradeCommand(args[1:], output)
	case "help", "--help", "-h":
		fmt.Fprintln(output, "ASWired Server\n  serve                     Start the local controller (default)\n  version                   Print build information\n  reset-password --username NAME --password-stdin [--data-dir DIR] [--clear-mfa]\n  upgrade --version vX.Y.Z [--output PATH]\nEnvironment: ASWIRED_DATA_DIR, ASWIRED_LISTEN, ASWIRED_PUBLIC_URL, ASWIRED_DATABASE_DRIVER, ASWIRED_DATABASE_DSN")
		return nil
	default:
		return fmt.Errorf("unknown command %q; use --help", args[0])
	}
}

func resetPasswordCommand(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	flags.SetOutput(output)
	username := flags.String("username", "", "existing account username")
	fromStdin := flags.Bool("password-stdin", false, "read a new password from standard input without command-line exposure")
	dir := flags.String("data-dir", "", "existing data directory")
	clearMFA := flags.Bool("clear-mfa", false, "also remove this account's TOTP and Passkeys")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *username == "" || !*fromStdin {
		return errors.New("specify --username and --password-stdin; a password command-line argument is deliberately unavailable")
	}
	if *dir != "" {
		if err := os.Setenv("ASWIRED_DATA_DIR", *dir); err != nil {
			return err
		}
	}
	chosenDir := os.Getenv("ASWIRED_DATA_DIR")
	if chosenDir == "" {
		chosenDir = "data"
	}
	if info, err := os.Stat(chosenDir); err != nil || !info.IsDir() {
		return errors.New("existing controller data directory not found")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 74))
	if err != nil {
		return err
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(password) < 12 || len(password) > 72 {
		return errors.New("password must contain 12 to 72 UTF-8 bytes")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.DatabaseDriver == "sqlite" {
		if _, err := os.Stat(cfg.DatabaseDSN); err != nil {
			return errors.New("existing SQLite database not found; reset does not initialize a new controller")
		}
	}
	db, err := store.Open(store.Config{Driver: cfg.DatabaseDriver, DSN: cfg.DatabaseDSN})
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	user, err := db.UserByUsername(ctx, *username)
	if err != nil {
		return errors.New("existing account not found")
	}
	tx, err := db.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, db.Bind(`UPDATE users SET password_hash=?,token_version=token_version+1,updated_at=? WHERE id=? AND token_version=?`), hash, time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"), user.ID, user.TokenVersion)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("account changed concurrently; retry after stopping the server")
	}
	if *clearMFA {
		if _, err := tx.ExecContext(ctx, db.Bind(`DELETE FROM records WHERE (collection=? AND id=?) OR (collection=? AND owner_id=?)`), "_identity", user.ID, "_passkeys", user.ID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fmt.Fprintln(output, "Password updated. Previous JWT sessions are revoked. Database and persistent keys are preserved.")
	if *clearMFA {
		fmt.Fprintln(output, "This account's TOTP and Passkeys were removed. Register them again after signing in.")
	}
	return nil
}

var releaseVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

const releaseRepository = "https://github.com/AyanamiReiChan/ASWired-Release/releases/download/"

func upgradeCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	flags.SetOutput(output)
	version := flags.String("version", "", "exact published vX.Y.Z release")
	target := flags.String("output", "", "binary destination; default is this executable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !releaseVersionPattern.MatchString(*version) {
		return errors.New("an exact release version such as --version v0.2.0 is required")
	}
	if *target == "" {
		if runtime.GOOS == "windows" {
			return errors.New("Windows cannot replace a running executable; specify --output for the staged binary, stop the service, then replace it")
		}
		path, err := os.Executable()
		if err != nil {
			return err
		}
		*target = path
	}
	destination, err := filepath.Abs(*target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	asset := "aswired-server_" + *version + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	if runtime.GOOS == "windows" {
		asset = strings.TrimSuffix(asset, ".tar.gz") + ".zip"
	}
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 6 {
			return errors.New("release download redirect rejected")
		}
		return nil
	}}
	base := releaseRepository + *version + "/"
	sums, err := downloadRelease(ctx, client, base+"SHA256SUMS", 1<<20)
	if err != nil {
		return err
	}
	expected, err := releaseChecksum(sums, asset)
	if err != nil {
		return err
	}
	archive, err := downloadRelease(ctx, client, base+asset, 128<<20)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(archive)
	if hex.EncodeToString(actual[:]) != expected {
		return errors.New("release checksum mismatch; existing binary remains unchanged")
	}
	binaryName := "aswired-server"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binary, err := extractReleaseBinary(archive, strings.HasSuffix(asset, ".zip"), binaryName)
	if err != nil {
		return err
	}
	if err := replaceBinary(destination, binary); err != nil {
		return err
	}
	fmt.Fprintf(output, "Verified %s and installed %s. Data and keys were preserved. Restart the service to activate the new binary.\n", *version, destination)
	return nil
}

func downloadRelease(ctx context.Context, client *http.Client, address string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("release artifact unavailable (HTTP %d); this version may not have been published or may be private; nothing was installed", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("release artifact exceeds size limit")
	}
	return data, nil
}

func releaseChecksum(raw []byte, asset string) (string, error) {
	found := ""
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 || strings.TrimPrefix(parts[1], "*") != asset {
			continue
		}
		if found != "" {
			return "", errors.New("duplicate release checksum entry")
		}
		decoded, err := hex.DecodeString(parts[0])
		if err != nil || len(decoded) != sha256.Size {
			return "", errors.New("invalid release SHA256")
		}
		found = strings.ToLower(parts[0])
	}
	if found == "" {
		return "", errors.New("release checksum entry missing; nothing was installed")
	}
	return found, nil
}

func extractReleaseBinary(raw []byte, zipped bool, name string) ([]byte, error) {
	var binary []byte
	read := func(reader io.Reader) error {
		if binary != nil {
			return errors.New("duplicate binary in release archive")
		}
		data, err := io.ReadAll(io.LimitReader(reader, 128<<20+1))
		if err != nil {
			return err
		}
		if len(data) == 0 || len(data) > 128<<20 {
			return errors.New("invalid binary size")
		}
		binary = data
		return nil
	}
	if zipped {
		archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return nil, err
		}
		for _, file := range archive.File {
			if file.Name != name {
				continue
			}
			if !file.Mode().IsRegular() {
				return nil, errors.New("release executable is not a regular file")
			}
			reader, err := file.Open()
			if err != nil {
				return nil, err
			}
			err = read(reader)
			reader.Close()
			if err != nil {
				return nil, err
			}
		}
	} else {
		gzipReader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		archive := tar.NewReader(gzipReader)
		for {
			header, err := archive.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if header.Name != name {
				continue
			}
			if header.Typeflag != tar.TypeReg {
				return nil, errors.New("release executable is not a regular file")
			}
			if err := read(archive); err != nil {
				return nil, err
			}
		}
	}
	if binary == nil {
		return nil, errors.New("release archive does not contain the exact executable name")
	}
	return binary, nil
}

func replaceBinary(path string, raw []byte) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to overwrite a symbolic link; choose its intended binary path")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".aswired-upgrade-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err = temporary.Chmod(0755); err == nil {
		_, err = temporary.Write(raw)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temporary.Name(), path)
}
