// Command locklyctl-mqtt is a self-hosted MQTT server and management backend
// for Lockly Wi-Fi locks. See CONTRACT.md for the wire protocol.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/config"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/server"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "create-operator":
		err = cmdCreateOperator(os.Args[2:])
	case "create-account":
		err = cmdCreateAccount(os.Args[2:])
	case "add-lock":
		err = cmdAddLock(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `locklyctl-mqtt - self-hosted MQTT server for Lockly locks

usage:
  locklyctl-mqtt serve [flags]
  locklyctl-mqtt create-operator -username U -password P [-db path]
  locklyctl-mqtt create-account  -email E -password P [-db path]
  locklyctl-mqtt add-lock -device-id ID -mc CODE -owner ACCT_ID [flags]

run a command with -h for its flags.
`)
}

func cmdServe(args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.StringVar(&cfg.HTTPAddr, "http", cfg.HTTPAddr, "HTTP listen address for the API and console")
	fs.StringVar(&cfg.HTTPSCert, "https-cert", "", "TLS cert for the HTTP server (optional)")
	fs.StringVar(&cfg.HTTPSKey, "https-key", "", "TLS key for the HTTP server (optional)")
	fs.StringVar(&cfg.MQTTAddr, "mqtt", cfg.MQTTAddr, "plaintext MQTT listen address (empty to disable)")
	fs.StringVar(&cfg.MQTTTLSAddr, "mqtt-tls", "", "TLS MQTT listen address, e.g. :8883 (optional)")
	fs.StringVar(&cfg.MQTTCert, "mqtt-cert", "", "cert for the MQTT TLS listener")
	fs.StringVar(&cfg.MQTTKey, "mqtt-key", "", "key for the MQTT TLS listener")
	fs.StringVar(&cfg.PublicMQTTHost, "public-mqtt-host", "", "host locks should connect to (getHeartbeatTime)")
	fs.IntVar(&cfg.PublicMQTTPort, "public-mqtt-port", cfg.PublicMQTTPort, "port locks should connect to")
	fs.IntVar(&cfg.HeartbeatSeconds, "heartbeat", cfg.HeartbeatSeconds, "MQTT heartbeat seconds handed to locks")
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path")
	_ = fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv, err := server.New(cfg, log)
	if err != nil {
		return err
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting locklyctl-mqtt")
	return srv.Run(ctx)
}

func openStore(args []string, fs *flag.FlagSet) (*store.Store, error) {
	db := fs.String("db", config.Default().DBPath, "SQLite database path")
	_ = fs.Parse(args)
	return store.Open(*db)
}

func cmdCreateOperator(args []string) error {
	fs := flag.NewFlagSet("create-operator", flag.ExitOnError)
	user := fs.String("username", "", "operator username")
	pass := fs.String("password", "", "operator password")
	st, err := openStore(args, fs)
	if err != nil {
		return err
	}
	defer st.Close()
	if *user == "" || *pass == "" {
		return fmt.Errorf("-username and -password are required")
	}
	hash, err := store.HashPassword(*pass)
	if err != nil {
		return err
	}
	if _, err := st.CreateOperator(*user, hash); err != nil {
		return err
	}
	fmt.Printf("operator %q created\n", *user)
	return nil
}

func cmdCreateAccount(args []string) error {
	fs := flag.NewFlagSet("create-account", flag.ExitOnError)
	email := fs.String("email", "", "account email (locklyctl signs in with this)")
	pass := fs.String("password", "", "account password")
	st, err := openStore(args, fs)
	if err != nil {
		return err
	}
	defer st.Close()
	if *email == "" || *pass == "" {
		return fmt.Errorf("-email and -password are required")
	}
	hash, err := store.HashAccountPassword(*pass)
	if err != nil {
		return err
	}
	acc, err := st.CreateAccount(*email, hash)
	if err != nil {
		return err
	}
	fmt.Printf("account %q created (id %d)\n", acc.Email, acc.ID)
	return nil
}

func cmdAddLock(args []string) error {
	fs := flag.NewFlagSet("add-lock", flag.ExitOnError)
	lk := &store.Lock{}
	fs.StringVar(&lk.DeviceID, "device-id", "", "lock device id (lowercase hex)")
	fs.StringVar(&lk.MC, "mc", "", "master code")
	fs.StringVar(&lk.BLEName, "blename", "", "Bluetooth name")
	fs.StringVar(&lk.Model, "model", "", "model, e.g. PGK728WRHK")
	fs.StringVar(&lk.TZ, "tz", "", "time zone, e.g. +8:00")
	fs.Int64Var(&lk.OwnerAccountID, "owner", 0, "owner account id")
	fs.StringVar(&lk.MQTTClientID, "mqtt-client-id", "", "the lock's MQTT client id")
	fs.StringVar(&lk.MQTTUsername, "mqtt-username", "", "the lock's MQTT username")
	fs.StringVar(&lk.MQTTPassword, "mqtt-password", "", "the lock's MQTT password")
	db := fs.String("db", config.Default().DBPath, "SQLite database path")
	_ = fs.Parse(args)
	if lk.DeviceID == "" || lk.MC == "" || lk.OwnerAccountID == 0 {
		return fmt.Errorf("-device-id, -mc and -owner are required")
	}
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.CreateLock(lk); err != nil {
		return err
	}
	fmt.Printf("lock %q registered under account %d\n", lk.DeviceID, lk.OwnerAccountID)
	return nil
}
