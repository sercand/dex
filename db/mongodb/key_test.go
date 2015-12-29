package mongodb

import (
	"testing"
)

func TestNewPrivateKeySetRepoInvalidKey(t *testing.T) {
	d := &MongoDBDriver{}
	_, err := d.NewPrivateKeySetRepo(false, []byte("sharks"))
	if err == nil {
		t.Errorf("Expected non-nil error for key secret that was not 32 bytes")
	}
	_, err = d.NewPrivateKeySetRepo(false)
	if err == nil {
		t.Fatalf("Expected non-nil error when creating repo with no key secrets")
	}
}
