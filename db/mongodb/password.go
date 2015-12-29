package mongodb

import (
	"time"
	"github.com/coreos/dex/repo"
	"github.com/coreos/dex/user"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/mgo.v2"
)

type passwordInfoModel struct {
	UserID          string `bson:"user_id"`
	Password        string `bson:"password"`
	PasswordExpires int64  `bson:"password_expires"`
}

func NewPasswordInfoRepo(driver *MongoDBDriver) user.PasswordInfoRepo {
	con := driver.Session.DB("").C(PasswordCollection)
	con.EnsureIndex(mgo.Index{
		Key:[]string{"user_id"},
		Unique:true,
	})
	return &passwordInfoRepo{
		driver: driver,
	}
}

func newPasswordInfoModel(p *user.PasswordInfo) (*passwordInfoModel, error) {
	pw := passwordInfoModel{
		UserID:   p.UserID,
		Password: string(p.Password),
	}

	if !p.PasswordExpires.IsZero() {
		pw.PasswordExpires = p.PasswordExpires.Unix()
	}

	return &pw, nil
}
func (p *passwordInfoModel) passwordInfo() (user.PasswordInfo, error) {
	pw := user.PasswordInfo{
		UserID:   p.UserID,
		Password: user.Password(p.Password),
	}

	if p.PasswordExpires != 0 {
		pw.PasswordExpires = time.Unix(p.PasswordExpires, 0).UTC()
	}

	return pw, nil
}

type passwordInfoRepo struct {
	driver *MongoDBDriver
}

func (r *passwordInfoRepo) Get(tx repo.Transaction, userID string) (user.PasswordInfo, error) {
	return r.get(tx, userID)
}

func (r *passwordInfoRepo) Create(tx repo.Transaction, pw user.PasswordInfo) (err error) {
	if pw.UserID == "" {
		return user.ErrorInvalidID
	}

	_, err = r.get(tx, pw.UserID)
	if err == nil {
		return user.ErrorDuplicateID
	}
	if err != user.ErrorNotFound {
		return err
	}

	pm, err := newPasswordInfoModel(&pw)
	if err != nil {
		return err
	}
	con := r.driver.Session.DB("").C(PasswordCollection)
	return con.Insert(pm)
}

func (r *passwordInfoRepo) Update(tx repo.Transaction, pw user.PasswordInfo) error {
	if pw.UserID == "" {
		return user.ErrorInvalidID
	}

	if len(pw.Password) == 0 {
		return user.ErrorInvalidPassword
	}

	// make sure this user exists already
	_, err := r.get(tx, pw.UserID)
	if err != nil {
		return err
	}

	err = r.update(tx, pw)
	if err != nil {
		return err
	}

	return nil
}

func (r *passwordInfoRepo) get(tx repo.Transaction, id string) (user.PasswordInfo, error) {
	con := r.driver.Session.DB("").C(PasswordCollection)
	var pwm passwordInfoModel
	err := con.Find(bson.M{"user_id":id}).One(&pwm)
	if err == mgo.ErrNotFound {
		return user.PasswordInfo{}, user.ErrorNotFound
	}
	if err != nil {
		return user.PasswordInfo{}, nil
	}
	return pwm.passwordInfo()
}

func (r *passwordInfoRepo) update(tx repo.Transaction, pw user.PasswordInfo) error {
	con := r.driver.Session.DB("").C(PasswordCollection)
	pm, err := newPasswordInfoModel(&pw)
	if err != nil {
		return err
	}
	return con.Update(bson.M{"user_id":pw.UserID}, pm)
}



