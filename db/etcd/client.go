package etcd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/coreos/dex/client"
	pcrypto "github.com/coreos/dex/pkg/crypto"
	"github.com/coreos/dex/pkg/log"
	etcdclient "github.com/coreos/etcd/client"
	"github.com/coreos/go-oidc/oidc"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"net/url"
	"path"
)

const (
	bcryptHashCost = 10

	// Blowfish, the algorithm underlying bcrypt, has a maximum
	// password length of 72. We explicitly track and check this
	// since the bcrypt library will silently ignore portions of
	// a password past the first 72 characters.
	maxSecretLength = 72
)

func newClientIdentityModel(id string, secret []byte, meta *oidc.ClientMetadata) (*clientIdentityModel, error) {
	hashed, err := bcrypt.GenerateFromPassword(secret, bcryptHashCost)
	if err != nil {
		return nil, err
	}

	bmeta, err := json.Marshal(newClientMetadataJSON(meta))
	if err != nil {
		return nil, err
	}

	cim := clientIdentityModel{
		ID:       id,
		Secret:   hashed,
		Metadata: string(bmeta),
	}

	return &cim, nil
}

type clientIdentityModel struct {
	ID       string `json:"id"`
	Secret   []byte `json:"secret"`
	Metadata string `json:"metadata"`
}

func newClientMetadataJSON(cm *oidc.ClientMetadata) *clientMetadataJSON {
	cmj := clientMetadataJSON{
		RedirectURLs: make([]string, len(cm.RedirectURLs)),
	}

	for i, u := range cm.RedirectURLs {
		cmj.RedirectURLs[i] = (&u).String()
	}

	return &cmj
}

type clientMetadataJSON struct {
	RedirectURLs []string `json:"redirectURLs"`
}

func (cmj clientMetadataJSON) ClientMetadata() (*oidc.ClientMetadata, error) {
	cm := oidc.ClientMetadata{
		RedirectURLs: make([]url.URL, len(cmj.RedirectURLs)),
	}

	for i, us := range cmj.RedirectURLs {
		up, err := url.Parse(us)
		if err != nil {
			return nil, err
		}
		cm.RedirectURLs[i] = *up
	}

	return &cm, nil
}

func (m *clientIdentityModel) ClientIdentity() (*oidc.ClientIdentity, error) {
	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID:     m.ID,
			Secret: string(m.Secret),
		},
	}

	var cmj clientMetadataJSON
	err := json.Unmarshal([]byte(m.Metadata), &cmj)
	if err != nil {
		return nil, err
	}

	cm, err := cmj.ClientMetadata()
	if err != nil {
		return nil, err
	}

	ci.Metadata = *cm
	return &ci, nil
}

func NewClientIdentityRepo(driver *EtcdDriver) *clientIdentityRepo {
	return &clientIdentityRepo{driver: driver}
}

func NewClientIdentityRepoFromClients(driver *EtcdDriver, clients []oidc.ClientIdentity) (client.ClientIdentityRepo, error) {
	repo := NewClientIdentityRepo(driver)
	for _, c := range clients {
		dec, err := base64.URLEncoding.DecodeString(c.Credentials.Secret)
		if err != nil {
			return nil, err
		}

		cm, err := newClientIdentityModel(c.Credentials.ID, dec, &c.Metadata)
		if err != nil {
			return nil, err
		}
		err = repo.insert(cm)
		if err != nil {
			return nil, err
		}
	}
	return repo, nil
}

type clientIdentityRepo struct {
	driver *EtcdDriver
}

func (r *clientIdentityRepo) dir() string {
	return path.Join(r.driver.directory, ClientIdentityDirectory, "identity")
}

func (r *clientIdentityRepo) key(id string) string {
	return path.Join(r.driver.directory, ClientIdentityDirectory, "identity", id)
}

func (r *clientIdentityRepo) admin(id string) string {
	return path.Join(r.driver.directory, ClientIdentityDirectory, "admin", id)
}

func (r *clientIdentityRepo) Metadata(clientID string) (*oidc.ClientMetadata, error) {
	cim, err := r.get(clientID)
	if cim == nil || err == client.ErrorNotFound {
		return nil, client.ErrorNotFound
	}
	if err != nil {
		return nil, err
	}

	ci, err := cim.ClientIdentity()
	if err != nil {
		return nil, err
	}

	return &ci.Metadata, nil
}

func (r *clientIdentityRepo) IsDexAdmin(clientID string) (bool, error) {
	resp, err := r.driver.kAPI.Get(context.Background(), r.admin(clientID), nil)
	if err != nil {
		return false, err
	}
	if resp == nil || resp.Node == nil {
		return false, client.ErrorNotFound
	}
	if resp.Node.Value == "1" {
		return true, nil
	}
	return false, nil
}

func (r *clientIdentityRepo) SetDexAdmin(clientID string, isAdmin bool) error {
	str := "0"
	if isAdmin {
		str = "1"
	}
	_, err := r.driver.kAPI.Set(context.Background(), r.admin(clientID), str, &etcdclient.SetOptions{PrevExist: etcdclient.PrevIgnore})
	return err
}

func (r *clientIdentityRepo) Authenticate(creds oidc.ClientCredentials) (bool, error) {
	cim, err := r.get(creds.ID)
	if err == client.ErrorNotFound {
		return false, nil
	}
	if cim == nil || err != nil {
		return false, err
	}

	dec, err := base64.URLEncoding.DecodeString(creds.Secret)
	if err != nil {
		log.Errorf("error Decoding client creds ")
		return false, nil
	}

	if len(dec) > maxSecretLength {
		return false, nil
	}

	ok := bcrypt.CompareHashAndPassword(cim.Secret, dec) == nil
	return ok, nil
}

func (r *clientIdentityRepo) New(id string, meta oidc.ClientMetadata) (*oidc.ClientCredentials, error) {
	secret, err := pcrypto.RandBytes(maxSecretLength)
	if err != nil {
		return nil, err
	}

	cim, err := newClientIdentityModel(id, secret, &meta)
	if err != nil {
		return nil, err
	}

	if err := r.insert(cim); err != nil {
		return nil, err
	}

	cc := oidc.ClientCredentials{
		ID:     id,
		Secret: base64.URLEncoding.EncodeToString(secret),
	}

	return &cc, nil
}

func (r *clientIdentityRepo) All() ([]oidc.ClientIdentity, error) {
	resp, err := r.driver.kAPI.Get(context.Background(), r.dir(), &etcdclient.GetOptions{Recursive: true})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Node == nil {
		return nil, client.ErrorNotFound
	}
	if !resp.Node.Dir {
		return nil, errors.New("node is not directory")
	}
	var cfgs []oidc.ClientIdentity
	for _, n := range resp.Node.Nodes {
		if n.Value != "" {
			var c clientIdentityModel
			err = json.Unmarshal([]byte(n.Value), &c)
			if err != nil {
				return nil, err
			}
			cc, err := c.ClientIdentity()
			if err != nil {
				return nil, err
			}
			cfgs = append(cfgs, *cc)
		}
	}
	return cfgs, nil
}

func (r *clientIdentityRepo) insert(cim *clientIdentityModel) error {
	b, err := json.Marshal(cim)
	if err != nil {
		return err
	}
	_, err = r.driver.kAPI.Create(context.Background(), r.key(cim.ID), string(b))
	return err
}

func (r *clientIdentityRepo) get(id string) (*clientIdentityModel, error) {
	kid := r.key(id)
	resp, err := r.driver.kAPI.Get(context.Background(), kid, nil)
	if err != nil {
		if cerr, ok := err.(etcdclient.Error); ok {
			if cerr.Code == etcdclient.ErrorCodeKeyNotFound {
				return nil, client.ErrorNotFound
			}
		}
		return nil, err
	}
	if resp == nil || resp.Node == nil {
		return nil, client.ErrorNotFound
	}
	var c clientIdentityModel
	err = json.Unmarshal([]byte(resp.Node.Value), &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
