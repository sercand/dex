package mongodb

import (
	_ "github.com/coreos/go-oidc/oidc"
)

/*
type localIdentityProvider struct {
	driver *MongoDBDriver
}

func (c *localIdentityProvider) Identity(email, password string) (*oidc.Identity, error) {
	user, err := c.driver.userManager.GetByEmail(email)
	if err != nil {
		return nil, err
	}

	id := user.ID

	pi, err := c.driver.userManager.GetPassword(id)
	if err != nil {
		return nil, err
	}

	return pi.Authenticate(password)
}
*/