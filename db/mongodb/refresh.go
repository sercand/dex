package mongodb

import (
	"encoding/base64"
	"fmt"
	"strings"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2/bson"
	"github.com/coreos/dex/refresh"
)

type refreshTokenRepo struct {
	driver         *MongoDBDriver
	tokenGenerator refresh.RefreshTokenGenerator
}
type refreshTokenModel struct {
	ID          bson.ObjectId     `bson:"_id"`
	PayloadHash []byte            `bson:"payload_hash"`
	UserID      string            `bson:"user_id"`
	ClientID    string            `bson:"client_id"`
}

// buildToken combines the token ID and token payload to create a new token.
func buildToken(tokenID bson.ObjectId, tokenPayload []byte) string {
	return fmt.Sprintf("%s%s%s", tokenID.Hex(), refresh.TokenDelimer, base64.URLEncoding.EncodeToString(tokenPayload))
}

// parseToken parses a token and returns the token ID and token payload.
func parseToken(token string) (bson.ObjectId, []byte, error) {
	parts := strings.SplitN(token, refresh.TokenDelimer, 2)
	if len(parts) != 2 {
		return "", nil, refresh.ErrorInvalidToken
	}
	if !bson.IsObjectIdHex(parts[0]) {
		return "", nil, refresh.ErrorInvalidToken
	}
	id := bson.ObjectIdHex(parts[0])
	tokenPayload, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, refresh.ErrorInvalidToken
	}
	return id, tokenPayload, nil
}

func checkTokenPayload(payloadHash, payload []byte) error {
	if err := bcrypt.CompareHashAndPassword(payloadHash, payload); err != nil {
		switch err {
		case bcrypt.ErrMismatchedHashAndPassword:
			return refresh.ErrorInvalidToken
		default:
			return err
		}
	}
	return nil
}

//newRefreshTokenRepo returns a new refreshTokenRepo with given parameters
func newRefreshTokenRepo(driver *MongoDBDriver) *refreshTokenRepo {
	return &refreshTokenRepo{
		driver:         driver,
		tokenGenerator: refresh.DefaultRefreshTokenGenerator,
	}
}

func (r *refreshTokenRepo) Create(userID, clientID string) (string, error) {
	if userID == "" {
		return "", refresh.ErrorInvalidUserID
	}
	if clientID == "" {
		return "", refresh.ErrorInvalidClientID
	}
	// Generate token.
	tokenPayload, err := r.tokenGenerator.Generate()
	if err != nil {
		return "", err
	}
	payloadHash, err := bcrypt.GenerateFromPassword(tokenPayload, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	tokenID := bson.NewObjectId()
	rtoken := refreshTokenModel{
		ID:          tokenID,
		PayloadHash: payloadHash,
		UserID:      userID,
		ClientID:    clientID,
	}

	cc := r.driver.Session.DB("").C(RefreshCollection)

	if err := cc.Insert(rtoken); err != nil {
		return "", nil
	}

	return buildToken(tokenID, tokenPayload), nil
}

func (r *refreshTokenRepo) Verify(clientID, token string) (string, error) {
	tokenID, tokenPayload, err := parseToken(token)
	if err != nil {
		return "", err
	}
	cc := r.driver.Session.DB("").C(RefreshCollection)
	var record refreshTokenModel

	if err := cc.FindId(tokenID).One(&record); err != nil {
		return "", refresh.ErrorInvalidToken
	}
	if record.ClientID != clientID {
		return "", refresh.ErrorInvalidClientID
	}

	if err := checkTokenPayload(record.PayloadHash, tokenPayload); err != nil {
		return "", err
	}

	return record.UserID, nil
}

func (r *refreshTokenRepo) Revoke(userID, token string) error {
	tokenID, tokenPayload, err := parseToken(token)
	if err != nil {
		return err
	}

	cc := r.driver.Session.DB("").C(RefreshCollection)
	var record refreshTokenModel

	if err := cc.FindId(tokenID).One(&record); err != nil {
		return refresh.ErrorInvalidToken
	}

	if record.UserID != userID {
		return refresh.ErrorInvalidUserID
	}

	if err := checkTokenPayload(record.PayloadHash, tokenPayload); err != nil {
		return err
	}

	if err := cc.RemoveId(record.ID); err != nil {
		return err
	}
	return nil
}
