package mongodb

import (
	"errors"
	"time"

	"github.com/jonboulle/clockwork"
	"gopkg.in/mgo.v2/bson"
	"github.com/coreos/dex/session"
	"encoding/json"
	"net/url"
	"github.com/coreos/go-oidc/oidc"
	"gopkg.in/mgo.v2"
)

type sessionModel struct {
	ID          string `bson:"_id"`
	State       string `bson:"state"`
	CreatedAt   time.Time  `bson:"created_at"`
	ExpiresAt   time.Time  `bson:"expires_at"`
	ClientID    string `bson:"client_id"`
	ClientState string `bson:"client_state"`
	RedirectURL string `bson:"redirect_url"`
	Identity    string `bson:"identity"`
	ConnectorID string `bson:"connector_id"`
	UserID      string `bson:"user_id"`
	Register    bool   `bson:"register"`
	Nonce       string `bson:"nonce"`
	Scope       []string `bson:"scope"`
}

func (s *sessionModel) session() (*session.Session, error) {
	ru, err := url.Parse(s.RedirectURL)
	if err != nil {
		return nil, err
	}

	var ident oidc.Identity
	if err = json.Unmarshal([]byte(s.Identity), &ident); err != nil {
		return nil, err
	}
	// If this is not here, then ExpiresAt is unmarshaled with a "loc" field,
	// which breaks tests.
	if ident.ExpiresAt.IsZero() {
		ident.ExpiresAt = time.Time{}
	}

	ses := session.Session{
		ID:          s.ID,
		State:       session.SessionState(s.State),
		ClientID:    s.ClientID,
		ClientState: s.ClientState,
		RedirectURL: *ru,
		Identity:    ident,
		ConnectorID: s.ConnectorID,
		UserID:      s.UserID,
		Register:    s.Register,
		Nonce:       s.Nonce,
		Scope:       s.Scope,
	}

	if !s.CreatedAt.IsZero() {
		ses.CreatedAt = s.CreatedAt.UTC()
	}
	if !s.ExpiresAt.IsZero() {
		ses.ExpiresAt = s.ExpiresAt.UTC()
	}
	return &ses, nil
}

func newSessionModel(s *session.Session) (*sessionModel, error) {
	b, err := json.Marshal(s.Identity)
	if err != nil {
		return nil, err
	}

	sm := sessionModel{
		ID:          s.ID,
		State:       string(s.State),
		ClientID:    s.ClientID,
		ClientState: s.ClientState,
		RedirectURL: s.RedirectURL.String(),
		Identity:    string(b),
		ConnectorID: s.ConnectorID,
		UserID:      s.UserID,
		Register:    s.Register,
		Nonce:       s.Nonce,
		Scope:       s.Scope,
	}

	if !s.CreatedAt.IsZero() {
		sm.CreatedAt = s.CreatedAt.UTC()
	}

	if !s.ExpiresAt.IsZero() {
		sm.ExpiresAt = s.ExpiresAt.UTC()
	}

	return &sm, nil
}

func newSessionRepo(driver *MongoDBDriver, clock clockwork.Clock) *sessionRepo {
	con := driver.Session.DB("").C(SessionCollection)
	con.EnsureIndex(mgo.Index{
		Key:[]string{"expires_at"},
		ExpireAfter:time.Second * 0,
	})
	return &sessionRepo{
		driver: driver,
		clock:  clock,
	}
}

type sessionRepo struct {
	driver *MongoDBDriver
	clock  clockwork.Clock
}

func (m *sessionRepo) Get(sessionID string) (*session.Session, error) {
	cc := m.driver.Session.DB("").C(SessionCollection)
	var sm sessionModel
	err := cc.FindId(sessionID).One(&sm)
	if err != nil {
		return nil, err
	}
	ses, err := sm.session()
	if err != nil {
		return nil, err
	}
	if ses.ExpiresAt.Before(m.clock.Now()) {
		return nil, errors.New("session does not exist")
	}
	return ses, nil
}

func (m *sessionRepo) Create(s session.Session) error {
	cc := m.driver.Session.DB("").C(SessionCollection)
	sm, err := newSessionModel(&s)
	if err != nil {
		return err
	}
	return cc.Insert(sm)
}

func (m *sessionRepo) Update(s session.Session) error {
	cc := m.driver.Session.DB("").C(SessionCollection)
	sm, err := newSessionModel(&s)
	if err != nil {
		return err
	}
	return cc.UpdateId(s.ID, sm)
}

//Session Key

type sessionKeyModel struct {
	Key       string        `bson:"key"`
	SessionID string        `bson:"session_id"`
	ExpiresAt time.Time     `bson:"expires_at"`
	Stale     bool          `bson:"stale"`
}

func newSessionKeyRepo(driver *MongoDBDriver, clock clockwork.Clock) *sessionKeyRepo {
	con := driver.Session.DB("").C(SessionKeyCollection)

	con.EnsureIndex(mgo.Index{
		Key:[]string{"expires_at"},
		ExpireAfter:time.Second * 0,
	})
	con.EnsureIndexKey("key")

	return &sessionKeyRepo{
		driver: driver,
		clock:  clock,
	}
}

type sessionKeyRepo struct {
	driver *MongoDBDriver
	clock  clockwork.Clock
}

func (r *sessionKeyRepo) Pop(key string) (string, error) {
	cc := r.driver.Session.DB("").C(SessionKeyCollection)
	var skm sessionKeyModel
	if err := cc.Find(bson.M{"key": key}).One(&skm); err != nil {
		return "", err
	}
	if skm.Stale || skm.ExpiresAt.Before(r.clock.Now()) {
		return "", errors.New("invalid session key")
	}

	err := cc.Update(bson.M{"stale": false, "key": key}, bson.M{"stale": true})
	if err != nil {
		return "", errors.New("failed to pop entity")
	}
	return skm.SessionID, nil
}

func (r *sessionKeyRepo) Push(sk session.SessionKey, exp time.Duration) error {
	cc := r.driver.Session.DB("").C(SessionKeyCollection)
	skm := &sessionKeyModel{
		Key:       sk.Key,
		SessionID: sk.SessionID,
		ExpiresAt: r.clock.Now().Add(exp),
		Stale:     false,
	}
	return cc.Insert(skm)
}
