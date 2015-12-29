package db

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/coreos/dex/client"
	"github.com/coreos/dex/connector"
	"github.com/coreos/dex/refresh"
	"github.com/coreos/dex/repo"
	"github.com/coreos/dex/session"
	"github.com/coreos/dex/user"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oidc"
	"github.com/jonboulle/clockwork"
)

type Driver interface {
	Name() string
	DoesNeedGarbageCollecting() bool

	NewConnectorConfigRepo() connector.ConnectorConfigRepo
	NewClientIdentityRepo() client.ClientIdentityRepo
	NewSessionRepo() session.SessionRepo
	NewSessionKeyRepo() session.SessionKeyRepo
	NewRefreshTokenRepo() refresh.RefreshTokenRepo
	NewPasswordInfoRepo() user.PasswordInfoRepo
	NewUserRepo() user.UserRepo
	NewPrivateKeySetRepo(useOldFormatKeySecrets bool, keySecrets ...[]byte) (key.PrivateKeySetRepo, error)

	NewUserRepoFromUsers(users []user.UserWithRemoteIdentities) (user.UserRepo, error)
	NewClientIdentityRepoFromClients(clients []oidc.ClientIdentity) (client.ClientIdentityRepo, error)
	NewSessionRepoWithClock(clockwork.Clock) session.SessionRepo
	NewSessionKeyRepoWithClock(clockwork.Clock) session.SessionKeyRepo

	GetTransactionFactory() repo.TransactionFactory
	DropTablesIfExists() error
	DropMigrationsTable() error
	MigrateToLatest() (int, error)
	NewGarbageCollector(interval time.Duration) GarbageCollector
}

type RegisteredDriver struct {
	New        func() (Driver, error)
	NewWithMap func(cnf map[string]interface{}) (Driver, error)
	InitFlags  func(fs *flag.FlagSet)
}

var (
	ErrorCannotDecryptKeys = errors.New("Cannot Decrypt Keys")
	drivers                map[string]*RegisteredDriver
)

func init() {
	drivers = make(map[string]*RegisteredDriver)
}

func Register(name string, rd *RegisteredDriver) error {
	if _, ext := drivers[name]; ext {
		return fmt.Errorf("Name already registered %s", name)
	}
	drivers[name] = rd
	return nil
}

func GetDriverNames() []string {
	drives := make([]string, 0)

	for name, _ := range drivers {
		drives = append(drives, name)
	}
	return drives
}

func GetDriver(name string) *RegisteredDriver {
	return drivers[name]
}

type GarbageCollector interface {
	Run() chan struct{}
}