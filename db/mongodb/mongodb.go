package mongodb

import (
	"fmt"
	"github.com/coreos/dex/db"
	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/go-oidc/key"
	"github.com/jonboulle/clockwork"
	mgo "gopkg.in/mgo.v2"
	"flag"
	"github.com/coreos/dex/connector"
	"github.com/coreos/dex/client"
	"github.com/coreos/dex/session"
	"github.com/coreos/dex/user"
	"github.com/coreos/dex/repo"
	"github.com/coreos/dex/refresh"
	"time"
	"github.com/coreos/go-oidc/oidc"
)

const (
	MongoDBDriverName string = "mongodb"
	mongoURLFlag string = "mongodb-url"
	ConnectorCollection string = "ConnectorConfig"
	ClientCollection string = "ClientIdentity"
	RefreshCollection string = "RefreshToken"
	UserCollection string = "User"
	SessionCollection string = "Session"
	SessionKeyCollection string = "SessionKey"
	TransactionCollection string = "Transactions"
	PasswordCollection string = "PasswordInfo"
	KeyCollection string = "Key"
)

var (
	dbUrl      *string
)

func init() {
	db.Register(MongoDBDriverName, &db.RegisteredDriver{
		New:        newMongoDriver,
		NewWithMap: newMongoDBDriverWithMap,
		InitFlags: initFlags,
	})
}
func initFlags(fs *flag.FlagSet) {
	dbUrl = fs.String(mongoURLFlag, "mongodb://127.0.0.1:2701/dex", "MongoDB URL")
}

func newMongoDriver() (db.Driver, error) {
	s, err := mgo.Dial(*dbUrl)

	if err != nil {
		return nil, err
	}
	log.Info("mongodb.go: connected to mongodb")
	md := &MongoDBDriver{
		Session: s,
	}
	return md, nil
}

func newMongoDBDriverWithMap(m map[string]interface{}) (db.Driver, error) {
	var url string

	if mm, ok := m["url"]; ok {
		url = mm.(string)
	}

	s, err := mgo.Dial(url)

	if err != nil {
		return nil, err
	}

	log.Info("mongodb.go: connected to mongodb on", url)

	md := &MongoDBDriver{
		Session: s,
	}

	return md, nil
}

type MongoDBDriver struct {
	Session *mgo.Session
}

func (d MongoDBDriver) Name() string {
	return MongoDBDriverName
}

func (d *MongoDBDriver) DoesNeedGarbageCollecting() bool {
	return false
}

func (d *MongoDBDriver) NewConnectorConfigRepo() connector.ConnectorConfigRepo {
	return &connectorConfigs{driver: d}
}

func (d *MongoDBDriver) NewClientIdentityRepo() client.ClientIdentityRepo {
	return &clientIdentityRepo{driver: d}
}

func (d *MongoDBDriver) NewSessionRepo() session.SessionRepo {
	return newSessionRepo(d, clockwork.NewRealClock())
}

func (d *MongoDBDriver) NewSessionKeyRepo() session.SessionKeyRepo {
	return newSessionKeyRepo(d, clockwork.NewRealClock())
}

func (m *MongoDBDriver) NewPasswordInfoRepo() user.PasswordInfoRepo {
	return NewPasswordInfoRepo(m)
}

func (d *MongoDBDriver) NewPrivateKeySetRepo(useOldFormatKeySecrets bool, secrets ...[]byte) (key.PrivateKeySetRepo, error) {
	for i, secret := range secrets {
		if len(secret) != 32 {
			return nil, fmt.Errorf("key secret %d: expected 32-byte secret", i)
		}
	}

	r := &mongoPrivateKeySetRepo{
		driver:  d,
		secrets: secrets,
	}
	return r, nil
}

func (m *MongoDBDriver) GetTransactionFactory() repo.TransactionFactory {
	return nil
}

func (d *MongoDBDriver) NewRefreshTokenRepo() refresh.RefreshTokenRepo {
	return newRefreshTokenRepo(d)
}

func (m *MongoDBDriver) NewUserRepo() user.UserRepo {
	return newUserRepo(m)
}

func (m *MongoDBDriver) DropTablesIfExists() error {
	db := m.Session.DB("")
	cns, err := db.CollectionNames()
	if err != nil {
		return err
	}
	for _, c := range cns {
		db.C(c).DropCollection()
	}
	return nil
}

func (m *MongoDBDriver) DropMigrationsTable() error {
	return nil
}

func (m *MongoDBDriver) MigrateToLatest() (int, error) {
	return 0, nil
}

func (m *MongoDBDriver) NewGarbageCollector(interval time.Duration) db.GarbageCollector {
	return nil
}

func (m *MongoDBDriver) NewUserRepoFromUsers(users []user.UserWithRemoteIdentities) (user.UserRepo, error) {
	return newUserRepoFromUsers(m, users)
}

func (m *MongoDBDriver) NewClientIdentityRepoFromClients(clients []oidc.ClientIdentity) (client.ClientIdentityRepo, error) {
	return NewClientIdentityRepoFromClients(m, clients)
}

func (m *MongoDBDriver) NewSessionRepoWithClock(clock clockwork.Clock) session.SessionRepo {
	return newSessionRepo(m, clock)
}

func (m *MongoDBDriver) NewSessionKeyRepoWithClock(clock clockwork.Clock) session.SessionKeyRepo {
	return newSessionKeyRepo(m, clock)
}

