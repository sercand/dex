package etcd

import (
	"flag"
	"time"

	"github.com/coreos/dex/client"
	"github.com/coreos/dex/connector"
	"github.com/coreos/dex/db"
	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/dex/refresh"
	"github.com/coreos/dex/repo"
	"github.com/coreos/dex/session"
	"github.com/coreos/dex/user"
	etcdclient "github.com/coreos/etcd/client"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oidc"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
	"strings"
)

const (
	DriverName = "etcd"
	EtcdUrlFlag = "etcd-url"
	EtcdDirectoryFlag = "etcd-directory"
	ConnectorConfigDirectory = "connector_config"
	ClientIdentityDirectory = "client_identity"
	SessionDirectory = "session"
	SessionKeyDirectory = "session_key"
	RefreshTokenDirectory = "refresh_token"
	KeyFile = "key"
)

var (
	etcdDirectory *string
	etcdUrl       *string
)

func init() {
	db.Register(DriverName, &db.RegisteredDriver{
		New:        newEtcdDriver,
		InitFlags:  initFlags,
		NewWithMap: newEtcdDriverWithMap,
	})
}

func initFlags(fs *flag.FlagSet) {
	etcdUrl = fs.String(EtcdUrlFlag, "http://127.0.0.1:2379", "etcd server url")
	etcdDirectory = fs.String(EtcdDirectoryFlag, "/dex", "root directory")
}

type EtcdDriver struct {
	client    etcdclient.Client
	kAPI      etcdclient.KeysAPI
	directory string
}

func newEtcdDriver() (db.Driver, error) {
	m := &EtcdDriver{
		directory: *etcdDirectory,
	}

	cfg := etcdclient.Config{
		Endpoints: strings.Split(*etcdUrl, ","),
		Transport: etcdclient.DefaultTransport,
	}

	c, err := etcdclient.New(cfg)
	if err != nil {
		return nil, err
	}
	m.client = c
	m.kAPI = etcdclient.NewKeysAPI(c)

	log.Debug("Connected to Etcd server")
	return m, nil
}

func newEtcdDriverWithMap(mc map[string]interface{}) (db.Driver, error) {
	m := &EtcdDriver{}
	if d, ok := mc["directory"]; ok {
		m.directory = d.(string)
	} else {
		m.directory = "/dex"
	}
	var ep []string
	if d, ok := mc["url"]; ok {
		ep = strings.Split(d.(string), ",")
	} else {
		ep = []string{"http://127.0.0.1:2379"}
	}

	cfg := etcdclient.Config{
		Endpoints: ep,
		Transport: etcdclient.DefaultTransport,
	}

	c, err := etcdclient.New(cfg)
	if err != nil {
		return nil, err
	}
	m.client = c
	m.kAPI = etcdclient.NewKeysAPI(c)

	log.Debug("Connected to Etcd server")
	return m, nil
}

func (e *EtcdDriver) Name() string {
	return DriverName
}

func (e *EtcdDriver) DoesNeedGarbageCollecting() bool {
	return false
}

func (e *EtcdDriver) NewConnectorConfigRepo() connector.ConnectorConfigRepo {
	return NewConnectorConfigRepo(e)
}

func (e *EtcdDriver) NewClientIdentityRepo() client.ClientIdentityRepo {
	return NewClientIdentityRepo(e)
}

func (e *EtcdDriver) NewSessionRepo() session.SessionRepo {
	return newSessionRepo(e, clockwork.NewRealClock())
}

func (e *EtcdDriver) NewSessionKeyRepo() session.SessionKeyRepo {
	return newSessionKeyRepo(e, clockwork.NewRealClock())
}

func (e *EtcdDriver) NewPasswordInfoRepo() user.PasswordInfoRepo {
	return nil
}

func (e *EtcdDriver) NewPrivateKeySetRepo(useOldFormatKeySecrets bool, keySecrets ...[]byte) (key.PrivateKeySetRepo, error) {
	return NewPrivateKeySetRepo(e, useOldFormatKeySecrets, keySecrets...)
}

func (e *EtcdDriver) GetTransactionFactory() repo.TransactionFactory {
	return repo.InMemTransactionFactory
}

func (e *EtcdDriver) NewRefreshTokenRepo() refresh.RefreshTokenRepo {
	return NewRefreshTokenRepo(e)
}

func (e *EtcdDriver) NewUserRepo() user.UserRepo {
	return nil
}

func (e *EtcdDriver) DropTablesIfExists() error {
	e.kAPI.Delete(context.Background(), e.directory, &etcdclient.DeleteOptions{
		Recursive: true,
		Dir:       true,
	})
	return nil
}

func (e *EtcdDriver) DropMigrationsTable() error {
	return nil
}

func (e *EtcdDriver) MigrateToLatest() (int, error) {
	return 0, nil
}

func (e *EtcdDriver) NewGarbageCollector(interval time.Duration) db.GarbageCollector {
	return nil
}

func (e *EtcdDriver) NewUserRepoFromUsers(users []user.UserWithRemoteIdentities) (user.UserRepo, error) {
	return user.NewUserRepoFromUsers(users), nil
}

func (e *EtcdDriver) NewClientIdentityRepoFromClients(clients []oidc.ClientIdentity) (client.ClientIdentityRepo, error) {
	return client.NewClientIdentityRepo(clients), nil
}

func (e *EtcdDriver) NewSessionRepoWithClock(clock clockwork.Clock) session.SessionRepo {
	return session.NewSessionRepoWithClock(clock)
}

func (e *EtcdDriver) NewSessionKeyRepoWithClock(clock clockwork.Clock) session.SessionKeyRepo {
	return session.NewSessionKeyRepoWithClock(clock)
}
