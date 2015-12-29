package etcd

import (
	"errors"
	"time"

	"encoding/json"
	"github.com/coreos/dex/session"
	etcdclient "github.com/coreos/etcd/client"
	"github.com/coreos/go-oidc/oidc"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
	"net/url"
	"path"
)

type sessionModel struct {
	ID          string   `json:"id"`
	State       string   `json:"state"`
	CreatedAt   int64    `json:"created_at"`
	ExpiresAt   int64    `json:"expires_at"`
	ClientID    string   `json:"client_id"`
	ClientState string   `json:"client_state"`
	RedirectURL string   `json:"redirect_url"`
	Identity    string   `json:"identity"`
	ConnectorID string   `json:"connector_id"`
	UserID      string   `json:"user_id"`
	Register    bool     `json:"register"`
	Nonce       string   `json:"nonce"`
	Scope       []string `json:"scope"`
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

	if s.CreatedAt != 0 {
		ses.CreatedAt = time.Unix(s.CreatedAt, 0).UTC()
	}

	if s.ExpiresAt != 0 {
		ses.ExpiresAt = time.Unix(s.ExpiresAt, 0).UTC()
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
		sm.CreatedAt = s.CreatedAt.Unix()
	}

	if !s.ExpiresAt.IsZero() {
		sm.ExpiresAt = s.ExpiresAt.Unix()
	}

	return &sm, nil
}

func newSessionRepo(driver *EtcdDriver, clock clockwork.Clock) *sessionRepo {
	sr := &sessionRepo{
		driver: driver,
		clock:  clock,
	}
	driver.kAPI.Set(context.Background(), sr.dir(), "", &etcdclient.SetOptions{
		PrevExist: etcdclient.PrevNoExist,
		Dir:       true,
	})
	return sr
}

type sessionRepo struct {
	driver *EtcdDriver
	clock  clockwork.Clock
}

func (r *sessionRepo) dir() string {
	return path.Join(r.driver.directory, SessionDirectory)
}

func (r *sessionRepo) key(id string) string {
	return path.Join(r.driver.directory, SessionDirectory, id)
}

func (m *sessionRepo) Get(sessionID string) (*session.Session, error) {
	sm, err := m.get(sessionID)
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
	sm, err := newSessionModel(&s)
	if err != nil {
		return err
	}
	return m.insert(sm)
}

func (m *sessionRepo) Update(s session.Session) error {
	sm, err := newSessionModel(&s)
	if err != nil {
		return err
	}
	return m.insert(sm)
}

func (r *sessionRepo) insert(sm *sessionModel) error {
	b, err := json.Marshal(sm)
	if err != nil {
		return err
	}
	_, err = r.driver.kAPI.Create(context.Background(), r.key(sm.ID), string(b))
	return err
}

func (r *sessionRepo) get(id string) (*sessionModel, error) {
	kid := r.key(id)
	resp, err := r.driver.kAPI.Get(context.Background(), kid, nil)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Node == nil {
		return nil, errors.New("session does not exist")
	}
	var c sessionModel
	err = json.Unmarshal([]byte(resp.Node.Value), &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

//Session Key

type sessionKeyModel struct {
	Key       string `json:"key"`
	SessionID string `json:"session_id"`
	ExpiresAt int64  `json:"expires_at"`
	Stale     bool   `json:"stale"`
}

func newSessionKeyRepo(driver *EtcdDriver, clock clockwork.Clock) *sessionKeyRepo {
	skr := &sessionKeyRepo{
		driver: driver,
		clock:  clock,
	}
	driver.kAPI.Set(context.Background(), skr.dir(), "", &etcdclient.SetOptions{
		PrevExist: etcdclient.PrevNoExist,
		Dir:       true,
	})
	return skr
}

type sessionKeyRepo struct {
	driver *EtcdDriver
	clock  clockwork.Clock
}

func (r *sessionKeyRepo) dir() string {
	return path.Join(r.driver.directory, SessionKeyDirectory)
}

func (r *sessionKeyRepo) key(id string) string {
	return path.Join(r.driver.directory, SessionKeyDirectory, id)
}

func (r *sessionKeyRepo) Pop(key string) (string, error) {
	skm, err := r.get(key)
	if err != nil {
		return "", err
	}

	if skm.Stale || skm.ExpiresAt < r.clock.Now().Unix() {
		return "", errors.New("invalid session key")
	}

	skm.Stale = true

	b, err := json.Marshal(skm)
	if err != nil {
		return "", err
	}
	_, err = r.driver.kAPI.Set(context.Background(), r.key(skm.Key), string(b), &etcdclient.SetOptions{
		PrevExist: etcdclient.PrevExist,
	})
	if err != nil {
		return "", err
	}
	return skm.SessionID, nil
}

func (r *sessionKeyRepo) Push(sk session.SessionKey, exp time.Duration) error {
	skm := &sessionKeyModel{
		Key:       sk.Key,
		SessionID: sk.SessionID,
		ExpiresAt: r.clock.Now().Unix() + int64(exp.Seconds()),
		Stale:     false,
	}
	b, err := json.Marshal(skm)
	if err != nil {
		return err
	}
	_, err = r.driver.kAPI.Set(context.Background(), r.key(skm.Key), string(b), &etcdclient.SetOptions{
		PrevExist: etcdclient.PrevNoExist,
		TTL:       exp,
	})
	return err
}

func (r *sessionKeyRepo) get(key string) (*sessionKeyModel, error) {
	kid := r.key(key)
	resp, err := r.driver.kAPI.Get(context.Background(), kid, nil)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Node == nil {
		return nil, errors.New("session does not exist")
	}
	var c sessionKeyModel
	err = json.Unmarshal([]byte(resp.Node.Value), &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
