package etcd

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	etcdclient "github.com/coreos/etcd/client"
	pcrypto "github.com/coreos/dex/pkg/crypto"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/dex/db"
	"path"
	"golang.org/x/net/context"
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

func NewPrivateKeySetRepo(driver *EtcdDriver, useOldFormat bool, secrets ...[]byte) (*PrivateKeySetRepo, error) {
	if len(secrets) == 0 {
		return nil, errors.New("must provide at least one key secret")
	}
	for i, secret := range secrets {
		if len(secret) != 32 {
			return nil, fmt.Errorf("key secret %d: expected 32-byte secret", i)
		}
	}

	r := &PrivateKeySetRepo{
		driver:        driver,
		useOldFormat: useOldFormat,
		secrets:      secrets,
	}

	return r, nil
}

type PrivateKeySetRepo struct {
	driver       *EtcdDriver
	useOldFormat bool
	secrets      [][]byte
}

func (r *PrivateKeySetRepo) path() string {
	return path.Join(r.driver.directory, KeyFile)
}

func (r *PrivateKeySetRepo) Set(ks key.KeySet) error {
	r.driver.kAPI.Delete(context.Background(), r.path(), nil)

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

	_, err = r.driver.kAPI.Set(context.Background(), r.path(), string(v), &etcdclient.SetOptions{
		PrevExist:etcdclient.PrevIgnore,
	})
	return err
}

func (r *PrivateKeySetRepo) Get() (key.KeySet, error) {
	resp, err := r.driver.kAPI.Get(context.Background(), r.path(), nil)
	if err != nil {
		if cerr, ok := err.(etcdclient.Error); ok {
			if cerr.Code == etcdclient.ErrorCodeKeyNotFound {
				return nil, key.ErrorNoKeys
			}
		}
		return nil, err
	}
	if resp == nil || resp.Node == nil {
		return nil, key.ErrorNoKeys
	}
	value := []byte(resp.Node.Value)

	var pks *key.PrivateKeySet
	for _, secret := range r.secrets {
		var j []byte

		if r.useOldFormat {
			j, err = pcrypto.AESDecrypt(value, secret)
		} else {
			j, err = pcrypto.Decrypt(value, secret)
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

func (r *PrivateKeySetRepo) active() []byte {
	return r.secrets[0]
}
