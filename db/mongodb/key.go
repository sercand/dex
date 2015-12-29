package mongodb

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	pcrypto "github.com/coreos/dex/pkg/crypto"
	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/dex/db"
)

func newPrivateKeySetModel(pks *key.PrivateKeySet) (*privateKeySetModel, error) {
	pkeys := pks.Keys()
	keys := make([]privateKeyModel, len(pkeys))
	for i, pkey := range pkeys {
		keys[i] = privateKeyModel{
			ID:    pkey.ID(),
			PKCS1: x509.MarshalPKCS1PrivateKey(pkey.PrivateKey),
		}
	}

	m := privateKeySetModel{
		Keys:      keys,
		ExpiresAt: pks.ExpiresAt(),
	}

	return &m, nil
}

type privateKeyModel struct {
	ID    string `json:"id"`
	PKCS1 []byte `json:"pkcs1"`
}

func (m *privateKeyModel) PrivateKey() (*key.PrivateKey, error) {
	d, err := x509.ParsePKCS1PrivateKey(m.PKCS1)
	if err != nil {
		return nil, err
	}

	pk := key.PrivateKey{
		KeyID:      m.ID,
		PrivateKey: d,
	}

	return &pk, nil
}

type privateKeySetModel struct {
	Keys      []privateKeyModel `json:"keys"`
	ExpiresAt time.Time         `json:"expires_at"`
}

func (m *privateKeySetModel) PrivateKeySet() (*key.PrivateKeySet, error) {
	keys := make([]*key.PrivateKey, len(m.Keys))
	for i, pkm := range m.Keys {
		pk, err := pkm.PrivateKey()
		if err != nil {
			return nil, err
		}
		keys[i] = pk
	}
	return key.NewPrivateKeySet(keys, m.ExpiresAt), nil
}

type privateKeySetBlob struct {
	Value []byte `bson:"value"`
}

type mongoPrivateKeySetRepo struct {
	driver  *MongoDBDriver
	useOldFormat bool
	secrets [][]byte
}

func (r *mongoPrivateKeySetRepo) Set(ks key.KeySet) error {
	col := r.driver.Session.DB("").C(KeyCollection)
	col.DropCollection()

	pks, ok := ks.(*key.PrivateKeySet)
	if !ok {
		return errors.New("unable to cast to PrivateKeySet")
	}

	m, err := newPrivateKeySetModel(pks)
	if err != nil {
		return err
	}

	j, err := json.Marshal(m)
	if err != nil {
		return err
	}

	var v []byte

	if r.useOldFormat {
		v, err = pcrypto.AESEncrypt(j, r.active())
	} else {
		v, err = pcrypto.Encrypt(j, r.active())
	}
	if err != nil {
		return err
	}

	return col.Insert(&privateKeySetBlob{Value: v})
}

func (r *mongoPrivateKeySetRepo) Get() (key.KeySet, error) {
	col := r.driver.Session.DB("").C(KeyCollection)
	var objs []*privateKeySetBlob
	col.Find(nil).All(&objs)
	if len(objs) == 0 {
		log.Error("mongodb/key.go: there no key at db")
		return nil, key.ErrorNoKeys
	}
	b := objs[0]

	var err error
	var pks *key.PrivateKeySet

	for _, secret := range r.secrets {
		var j []byte

		if r.useOldFormat {
			j, err = pcrypto.AESDecrypt(b.Value, secret)
		} else {
			j, err = pcrypto.Decrypt(b.Value, secret)
		}

		if err != nil {
			continue
		}

		var m privateKeySetModel
		if err = json.Unmarshal(j, &m); err != nil {
			continue
		}

		pks, err = m.PrivateKeySet()
		if err != nil {
			continue
		}
		break
	}

	if err != nil {
		return nil, db.ErrorCannotDecryptKeys
	}
	return key.KeySet(pks), nil
}

func (r *mongoPrivateKeySetRepo) active() []byte {
	return r.secrets[0]
}
