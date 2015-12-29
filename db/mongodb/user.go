package mongodb

import (
	"github.com/coreos/dex/user"
	"github.com/jonboulle/clockwork"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"github.com/coreos/dex/repo"
	"time"
)

func newUserRepo(driver *MongoDBDriver) *userRepo {
	return &userRepo{
		driver:            driver,
	}
}
func newUserRepoFromUsers(driver *MongoDBDriver, us []user.UserWithRemoteIdentities) (user.UserRepo, error) {
	repo := newUserRepo(driver)
	con := driver.Session.DB("").C(UserCollection)
	for _, u := range us {
		um := newUserModel(&u.User)
		err := con.Insert(um)
		for _, ri := range u.RemoteIdentities {
			err = repo.AddRemoteIdentity(nil, u.User.ID, ri)
			if err != nil {
				return nil, err
			}
		}
	}
	return repo, nil
}

type userRepo struct {
	driver            *MongoDBDriver
	clock             clockwork.Clock
	minPasswordLength int
}

func (m *userRepo) Get(tx repo.Transaction, userID string) (user.User, error) {
	c := m.driver.Session.DB("").C(UserCollection)
	var um userModel
	if err := c.FindId(userID).One(&um); err != nil {
		if err == mgo.ErrNotFound {
			return user.User{}, user.ErrorNotFound
		}
		return user.User{}, err
	}
	return um.user(), nil
}

func (m *userRepo) Create(tx repo.Transaction, usr user.User) (err error) {
	if usr.ID == "" {
		return user.ErrorInvalidID
	}
	c := m.driver.Session.DB("").C(UserCollection)

	var usr2 userModel
	err = c.FindId(usr.ID).One(&usr2)
	if err == nil {
		return user.ErrorDuplicateID
	}
	if err != mgo.ErrNotFound {
		return err
	}

	if !user.ValidEmail(usr.Email) {
		return user.ErrorInvalidEmail
	}

	// make sure there's no other user with the same Email
	_, err = m.GetByEmail(tx, usr.Email)
	if err == nil {
		return user.ErrorDuplicateEmail
	}
	if err != user.ErrorNotFound {
		return err
	}

	return c.Insert(newUserModel(&usr))
}

func (m *userRepo) Disable(tx repo.Transaction, userID string, disable bool) error {
	if userID == "" {
		return user.ErrorInvalidID
	}

	c := m.driver.Session.DB("").C(UserCollection)
	if err := c.UpdateId(userID, bson.M{"disabled": disable}); err != nil {
		if err == mgo.ErrNotFound {
			return user.ErrorNotFound
		}
		return err
	}
	return nil
}

func (m *userRepo) GetByEmail(tx repo.Transaction, email string) (user.User, error) {
	c := m.driver.Session.DB("").C(UserCollection)
	var usr userModel
	if err := c.Find(bson.M{"email": email}).One(&usr); err != nil {
		if err == mgo.ErrNotFound {
			return user.User{}, user.ErrorNotFound
		}
		return user.User{}, err
	}
	return usr.user(), nil
}

func (m *userRepo) Update(tx repo.Transaction, usr user.User) error {
	c := m.driver.Session.DB("").C(UserCollection)
	if usr.ID == "" {
		return user.ErrorInvalidID
	}
	if !user.ValidEmail(usr.Email) {
		return user.ErrorInvalidEmail
	}
	// make sure this user exists already
	var usrOther userModel
	var usrOther2 userModel
	if err := c.FindId(usr.ID).One(&usrOther); err != nil {
		if err == mgo.ErrNotFound {
			return user.ErrorNotFound
		}
		return err
	}

	// make sure there's no other user with the same Email
	if err := c.Find(bson.M{"email": usr.Email}).One(&usrOther2); err != mgo.ErrNotFound {
		if err != nil {
			return err
		}
		if usrOther2.ID != usr.ID {
			return user.ErrorDuplicateEmail
		}
	}

	return c.UpdateId(usr.ID, newUserModel(&usr))
}

func (m *userRepo) GetByRemoteIdentity(tx repo.Transaction, ri user.RemoteIdentity) (user.User, error) {
	c := m.driver.Session.DB("").C(UserCollection)

	var usr userModel
	err := c.Find(bson.M{
		"remote_identities": bson.M{
			"$elemMatch": newRemoteIdentity(ri),
		}},
	).One(&usr)

	if err == mgo.ErrNotFound {
		return user.User{}, user.ErrorNotFound
	}
	if err != nil {
		return user.User{}, err
	}
	return usr.user(), nil
}

func (m *userRepo) AddRemoteIdentity(tx repo.Transaction, userID string, ri user.RemoteIdentity) error {
	c := m.driver.Session.DB("").C(UserCollection)

	_, err := m.GetByRemoteIdentity(tx, ri)
	if err == nil {
		return user.ErrorDuplicateRemoteIdentity
	}
	if err != user.ErrorNotFound {
		return err
	}

	err = c.UpdateId(userID,
		bson.M{"$push": bson.M{"remote_identities": newRemoteIdentity(ri)}})
	if err == mgo.ErrNotFound {
		return user.ErrorNotFound
	}
	return err
}

func (m *userRepo) RemoveRemoteIdentity(tx repo.Transaction, userID string, rid user.RemoteIdentity) error {
	if userID == "" || rid.ID == "" || rid.ConnectorID == "" {
		return user.ErrorInvalidID
	}

	otherUserID, err := m.getUserIDForRemoteIdentity(tx, rid)
	if err != nil {
		return err
	}
	if otherUserID != userID {
		return user.ErrorNotFound
	}

	c := m.driver.Session.DB("").C(UserCollection)

	ci, err := c.UpdateAll(bson.M{"_id":userID}, bson.M{"$pull": bson.M{"remote_identities": newRemoteIdentity(rid)}})
	if err == mgo.ErrNotFound {
		return user.ErrorNotFound
	}
	if err != nil {
		return err
	}
	if ci == nil || ci.Updated == 0 {
		return user.ErrorNotFound
	}
	return nil
}

func (m *userRepo) GetRemoteIdentities(tx repo.Transaction, userID string) ([]user.RemoteIdentity, error) {
	c := m.driver.Session.DB("").C(UserCollection)
	var usr userModel
	if err := c.FindId(userID).Select(bson.M{"remote_identities": 1}).One(&usr); err != nil {
		if err == mgo.ErrNotFound {
			return nil, user.ErrorNotFound
		}
		return nil, err
	}
	var ris []user.RemoteIdentity
	for _, m := range usr.RemoteIdentities {
		ris = append(ris, m.Remote())
	}
	return ris, nil
}

func (m *userRepo) GetAdminCount(tx repo.Transaction) (int, error) {
	c := m.driver.Session.DB("").C(UserCollection)
	return c.Find(bson.M{"admin": true}).Count()
}

func (m *userRepo) List(tx repo.Transaction, filter user.UserFilter, maxResults int, nextPageToken string) ([]user.User, string, error) {
	var offset int
	var err error
	if nextPageToken != "" {
		filter, maxResults, offset, err = user.DecodeNextPageToken(nextPageToken)
	}
	if err != nil {
		return nil, "", err
	}
	var users []userModel
	c := m.driver.Session.DB("").C(UserCollection)
	if err := c.Find(bson.M{}).Limit(maxResults + 1).Skip(offset).All(&users); err != nil {
		if err == mgo.ErrNotFound {
			return nil, "", user.ErrorNotFound
		}
		return nil, "", err
	}
	if len(users) == 0 {
		return nil, "", user.ErrorNotFound
	}

	var more bool
	var numUsers int
	if len(users) <= maxResults {
		numUsers = len(users)
	} else {
		numUsers = maxResults
		more = true
	}

	var tok string
	if more {
		tok, err = user.EncodeNextPageToken(filter, maxResults, offset + maxResults)
		if err != nil {
			return nil, "", err
		}
	}
	result := make([]user.User, numUsers)
	for i := 0; i < numUsers; i += 1 {
		result[i] = users[i].user()
	}
	return result, tok, nil
}

func (m *userRepo) getUserIDForRemoteIdentity(tx repo.Transaction, ri user.RemoteIdentity) (string, error) {
	c := m.driver.Session.DB("").C(UserCollection)

	var usr userModel
	err := c.Find(bson.M{
		"remote_identities": bson.M{
			"$elemMatch": newRemoteIdentity(ri),
		}},
	).Select(bson.M{"_id":1}).One(&usr)

	if err == mgo.ErrNotFound {
		return "", user.ErrorNotFound
	}
	if err != nil {
		return "", err
	}
	return usr.ID, nil
}

type userModel struct {
	ID               string `bson:"_id"`
	Email            string `bson:"email"`
	EmailVerified    bool   `bson:"email_verified"`
	DisplayName      string `bson:"display_name"`
	Disabled         bool   `bson:"disabled"`
	Admin            bool   `bson:"admin"`
	CreatedAt        time.Time  `bson:"created_at"`
	RemoteIdentities []*remoteIdentity `bson:"remote_identities,omitempty"`
}

func (u *userModel) user() user.User {
	usr := user.User{
		ID:            u.ID,
		DisplayName:   u.DisplayName,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Admin:         u.Admin,
		Disabled:      u.Disabled,
	}
	if !u.CreatedAt.IsZero() {
		usr.CreatedAt = u.CreatedAt.UTC()
	}
	return usr
}

func newUserModel(u *user.User) *userModel {
	um := userModel{
		ID:            u.ID,
		DisplayName:   u.DisplayName,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Admin:         u.Admin,
		Disabled:      u.Disabled,
	}

	if !u.CreatedAt.IsZero() {
		um.CreatedAt = u.CreatedAt
	}

	return &um
}

func newRemoteIdentity(ri user.RemoteIdentity) *remoteIdentity {
	return &remoteIdentity{
		ConnectorID: ri.ConnectorID,
		RemoteID:    ri.ID,
	}
}

type remoteIdentity struct {
	ConnectorID string `bson:"connector_id"`
	RemoteID    string `bson:"remote_id"`
}

func (ri *remoteIdentity) Remote() user.RemoteIdentity {
	return user.RemoteIdentity{
		ConnectorID:ri.ConnectorID,
		ID:ri.RemoteID,
	}
}
