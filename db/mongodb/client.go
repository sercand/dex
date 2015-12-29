package mongodb

import (
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"

	pcrypto "github.com/coreos/dex/pkg/crypto"
	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/go-oidc/oidc"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"encoding/json"
	"net/url"
	"github.com/coreos/dex/client"
)

const (
	bcryptHashCost = 10

// Blowfish, the algorithm underlying bcrypt, has a maximum
// password length of 72. We explicitly track and check this
// since the bcrypt library will silently ignore portions of
// a password past the first 72 characters.
	maxSecretLength = 72
)

type clientIdentityRepo struct {
	driver *MongoDBDriver
}

type clientIdentityModel struct {
	ID       string `bson:"_id"`
	Secret   []byte `bson:"secret"`
	Metadata string `bson:"metadata"`
	DexAdmin bool   `bson:"dex_admin"`
}

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

// Metadata returns one matching ClientMetadata if the given client
// exists, otherwise nil. The returned error will be non-nil only
// if the repo was unable to determine client existence.
func (r *clientIdentityRepo) Metadata(clientID string) (*oidc.ClientMetadata, error) {
	var cim clientIdentityModel
	cc := r.driver.Session.DB("").C(ClientCollection)
	err := cc.FindId(clientID).Select(bson.M{"metadata": 1}).One(&cim)
	if err == mgo.ErrNotFound {
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

// All returns all registered Client Identities.
func (r *clientIdentityRepo) All() ([]oidc.ClientIdentity, error) {
	var clients []clientIdentityModel
	cc := r.driver.Session.DB("").C(ClientCollection)
	err := cc.Find(nil).All(&clients)
	if err != nil {
		return nil, err
	}
	result := make([]oidc.ClientIdentity, len(clients))

	for i, ci := range clients {
		o, err := ci.ClientIdentity()
		if err != nil {
			return nil, err
		}
		result[i] = *o
	}

	return result, nil
}

// New registers a ClientIdentity with the repo for the given metadata.
// An unused ID must be provided. A corresponding secret will be returned
// in a ClientCredentials struct along with the provided ID.
func (r *clientIdentityRepo) New(id string, meta oidc.ClientMetadata) (*oidc.ClientCredentials, error) {
	con := r.driver.Session.DB("").C(ClientCollection)

	secret, err := pcrypto.RandBytes(maxSecretLength)
	if err != nil {
		return nil, err
	}

	cim, err := newClientIdentityModel(id, secret, &meta)
	if err != nil {
		return nil, err
	}

	if err := con.Insert(cim); err != nil {
		return nil, err
	}

	cc := oidc.ClientCredentials{
		ID:     id,
		Secret: base64.URLEncoding.EncodeToString(secret),
	}

	return &cc, nil
}

// Authenticate asserts that a client with the given ID exists and
// that the provided secret matches. If either of these assertions
// fail, (false, nil) will be returned. Only if the repo is unable
// to make these assertions will a non-nil error be returned.
func (r *clientIdentityRepo) Authenticate(creds oidc.ClientCredentials) (bool, error) {
	con := r.driver.Session.DB("").C(ClientCollection)
	var cim clientIdentityModel
	err := con.FindId(creds.ID).One(&cim)
	if err == mgo.ErrNotFound {
		return false, nil
	}
	if err != nil {
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

func (r *clientIdentityRepo) IsDexAdmin(clientID string) (bool, error) {
	var cim clientIdentityModel
	cc := r.driver.Session.DB("").C(ClientCollection)
	err := cc.FindId(clientID).Select(bson.M{"dex_admin": 1}).One(&cim)

	if err == mgo.ErrNotFound {
		return false, client.ErrorNotFound
	}
	if err != nil {
		return false, err
	}

	return cim.DexAdmin, nil
}

func (r *clientIdentityRepo) SetDexAdmin(clientID string, isAdmin bool) error {
	cc := r.driver.Session.DB("").C(ClientCollection)
	return cc.UpdateId(clientID, bson.M{"dex_admin": isAdmin})
}

func NewClientIdentityRepoFromClients(driver *MongoDBDriver, clients []oidc.ClientIdentity) (client.ClientIdentityRepo, error) {
	repo := &clientIdentityRepo{driver: driver}
	con := driver.Session.DB("").C(ClientCollection)
	for _, c := range clients {
		dec, err := base64.URLEncoding.DecodeString(c.Credentials.Secret)
		if err != nil {
			return nil, err
		}

		cm, err := newClientIdentityModel(c.Credentials.ID, dec, &c.Metadata)
		if err != nil {
			return nil, err
		}
		err = con.Insert(cm)
		if err != nil {
			return nil, err
		}
	}
	return repo, nil
}