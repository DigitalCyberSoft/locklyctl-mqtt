// Command locklyctl-mqtt is a self-hosted MQTT server and management backend
// for Lockly Wi-Fi locks. See CONTRACT.md for the wire protocol.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/backup"
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
	case "export":
		err = cmdExport(os.Args[2:])
	case "import":
		err = cmdImport(os.Args[2:])
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
  locklyctl-mqtt export -account EMAIL -out FILE [-no-encrypt] [-passphrase-file F]
  locklyctl-mqtt import -account EMAIL -in FILE [-replace [-yes]] [-passphrase-file F]

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
	var acmeDomains string
	fs.StringVar(&acmeDomains, "acme-domains", "", "comma-separated domains for Let's Encrypt TLS (enables ACME; needs -mqtt-tls and -acme-accept-tos)")
	fs.StringVar(&cfg.ACME.Email, "acme-email", "", "ACME account email (optional)")
	fs.StringVar(&cfg.ACME.CacheDir, "acme-cache", cfg.ACME.CacheDir, "directory to cache issued ACME certificates")
	fs.StringVar(&cfg.ACME.DirectoryURL, "acme-directory", "", "ACME directory URL (default Let's Encrypt production; set for staging)")
	fs.StringVar(&cfg.ACME.HTTPAddr, "acme-http", cfg.ACME.HTTPAddr, "listen address for the ACME HTTP-01 challenge")
	fs.BoolVar(&cfg.ACME.AcceptTOS, "acme-accept-tos", false, "agree to the CA's terms of service (required to enable ACME)")
	_ = fs.Parse(args)
	if acmeDomains != "" {
		cfg.ACME.Domains = splitAndTrim(acmeDomains)
	}

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

// cmdExport writes an account's locks and people to a backup file (CONTRACT.md
// section 4): sealed with a passphrase unless -no-encrypt.
func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	email := fs.String("account", "", "the account to back up (its email)")
	out := fs.String("out", "", "the file to write (it must not exist yet)")
	noEnc := fs.Bool("no-encrypt", false, "write it unencrypted (it holds master codes and PINs)")
	passFile := fs.String("passphrase-file", "", "read the passphrase from this file (else it's asked for)")
	db := fs.String("db", config.Default().DBPath, "SQLite database path")
	_ = fs.Parse(args)
	if *email == "" || *out == "" {
		return fmt.Errorf("-account and -out are required")
	}
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	acc, err := st.GetAccountByEmail(*email)
	if err != nil {
		return fmt.Errorf("no account %q on this server", *email)
	}
	locks, err := st.ExportAccount(acc.ID)
	if err != nil {
		return err
	}
	doc := backup.FromStore(locks, backup.Source{Kind: "locklyctl-mqtt", Account: acc.Email}, time.Now())
	var data []byte
	if *noEnc {
		fmt.Fprintln(os.Stderr, "warning: writing the backup unencrypted. It holds master codes and PINs: "+
			"keep it private and out of version control.")
		data, err = backup.Marshal(doc)
	} else {
		var pass string
		if pass, err = passphrase(*passFile, true); err != nil {
			return err
		}
		data, err = backup.Seal(doc, pass)
	}
	if err != nil {
		return err
	}
	if err := writeNew(*out, data); err != nil {
		return err
	}
	people := 0
	for _, l := range locks {
		people += len(l.People)
	}
	how := "encrypted"
	if *noEnc {
		how = "NOT encrypted"
	}
	fmt.Printf("backed up %d lock(s) and %d person(s) of %s to %s (%s)\n", len(locks), people, acc.Email, *out, how)
	return nil
}

// cmdImport brings a backup into an account: merged by device id, or with
// -replace made exactly the backup's. Nothing is sent to any lock.
func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	email := fs.String("account", "", "the account to import into (its email; create it first)")
	in := fs.String("in", "", "the backup file to read")
	replace := fs.Bool("replace", false, "make the account exactly the backup's: locks and people not in it are deleted")
	yes := fs.Bool("yes", false, "don't ask before -replace")
	passFile := fs.String("passphrase-file", "", "read the passphrase from this file (else it's asked for)")
	db := fs.String("db", config.Default().DBPath, "SQLite database path")
	_ = fs.Parse(args)
	if *email == "" || *in == "" {
		return fmt.Errorf("-account and -in are required")
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	pass := ""
	if backup.Encrypted(data) {
		if pass, err = passphrase(*passFile, false); err != nil {
			return err
		}
	}
	doc, err := backup.Open(data, pass)
	if err != nil {
		return err
	}
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	acc, err := st.GetAccountByEmail(*email)
	if err != nil {
		return fmt.Errorf("no account %q on this server (create it first with create-account)", *email)
	}
	if *replace && !*yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("-replace needs -yes when it can't ask")
		}
		fmt.Fprintf(os.Stderr, "Make %s's locks and people exactly the backup's? Locks and people that "+
			"aren't in it are deleted. Type yes to go ahead: ", acc.Email)
		var answer string
		_, _ = fmt.Fscanln(os.Stdin, &answer)
		if answer != "yes" {
			fmt.Println("nothing changed")
			return nil
		}
	}
	res, err := st.ImportAccount(acc.ID, doc.ToStore(), *replace)
	if err != nil {
		return err
	}
	fmt.Printf("locks: %d added, %d updated, %d removed; people: %d added, %d updated, %d removed\n",
		res.LocksAdded, res.LocksUpdated, res.LocksRemoved, res.PeopleAdded, res.PeopleUpdated, res.PeopleRemoved)
	for _, d := range res.Conflicts {
		fmt.Printf("skipped lock %s: another account on this server has it\n", d)
	}
	if len(res.Conflicts) > 0 {
		return fmt.Errorf("%d lock(s) skipped; the rest were imported", len(res.Conflicts))
	}
	return nil
}

// passphrase reads a backup passphrase from a file, or asks on the terminal
// without echo (twice when confirm is set).
func passphrase(file string, confirm bool) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		p := strings.TrimRight(string(b), "\r\n")
		if p == "" {
			return "", errors.New("the passphrase file is empty")
		}
		return p, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("needs -passphrase-file when it can't ask for the passphrase")
	}
	fmt.Fprint(os.Stderr, "Backup passphrase: ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(p1) == 0 {
		return "", errors.New("the passphrase is empty")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "The same passphrase again: ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(p1) != string(p2) {
			return "", errors.New("the two passphrases differ")
		}
	}
	return string(p1), nil
}

// writeNew writes data to a file that must not exist yet, owner-only.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists: choose another name", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func splitAndTrim(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
	fs.StringVar(&lk.Name, "name", "", "the door's name, e.g. Front (optional)")
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
