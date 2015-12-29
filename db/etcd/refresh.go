package etcd

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/coreos/dex/refresh"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"time"
	etcdclient "github.com/coreos/etcd/client"
)

type refreshTokenRepo struct {
	driver         *EtcdDriver
	tokenGenerator refresh.RefreshTokenGenerator
}

// objectIdCounter is atomically incremented when generating a new ObjectId
// using NewObjectId() function. It's used as a counter part of an id.
var objectIdCounter uint32 = readRandomUint32()

// readRandomUint32 returns a random objectIdCounter.
func readRandomUint32() uint32 {
	var b [4]byte
	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		panic(fmt.Errorf("cannot read random object id: %v", err))
	}
	return uint32((uint32(b[0]) << 0) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24))
}

// machineId stores machine id generated once and used in subsequent calls
// to NewObjectId function.
var machineId = readMachineId()

// readMachineId generates and returns a machine id.
// If this function fails to get the hostname it will cause a runtime error.
func readMachineId() []byte {
	var sum [3]byte
	id := sum[:]
	hostname, err1 := os.Hostname()
	if err1 != nil {
		_, err2 := io.ReadFull(rand.Reader, id)
		if err2 != nil {
			panic(fmt.Errorf("cannot get hostname: %v; %v", err1, err2))
		}
		return id
	}
	hw := md5.New()
	hw.Write([]byte(hostname))
	copy(id, hw.Sum(nil))
	return id
}

func NewRefreshTokenId() string {
	var b [12]byte
	// Timestamp, 4 bytes, big endian
	binary.BigEndian.PutUint32(b[:], uint32(time.Now().Unix()))
	// Machine, first 3 bytes of md5(hostname)
	b[4] = machineId[0]
	b[5] = machineId[1]
	b[6] = machineId[2]
	// Pid, 2 bytes, specs don't specify endianness, but we use big endian.
	pid := os.Getpid()
	b[7] = byte(pid >> 8)
	b[8] = byte(pid)
	// Increment, 3 bytes, big endian
	i := atomic.AddUint32(&objectIdCounter, 1)
	b[9] = byte(i >> 16)
	b[10] = byte(i >> 8)
	b[11] = byte(i)
	return hex.EncodeToString(b[:])
}

type refreshTokenModel struct {
	ID          string `json:"id"`
	PayloadHash []byte `json:"payload_hash"`
	UserID      string `json:"user_id"`
	ClientID    string `json:"client_id"`
}

func (r *refreshTokenRepo) dir() string {
	return path.Join(r.driver.directory, RefreshTokenDirectory)
}

func (r *refreshTokenRepo) key(id string) string {
	return path.Join(r.driver.directory, RefreshTokenDirectory, id)
}

// buildToken combines the token ID and token payload to create a new token.
func buildToken(tokenID string, tokenPayload []byte) string {
	return fmt.Sprintf("%s%s%s", tokenID, refresh.TokenDelimer, base64.URLEncoding.EncodeToString(tokenPayload))
}

// parseToken parses a token and returns the token ID and token payload.
func parseToken(token string) (string, []byte, error) {
	parts := strings.SplitN(token, refresh.TokenDelimer, 2)
	if len(parts) != 2 {
		return "", nil, refresh.ErrorInvalidToken
	}
	id := parts[0]
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

func NewRefreshTokenRepo(driver *EtcdDriver) refresh.RefreshTokenRepo {
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

	tokenPayload, err := r.tokenGenerator.Generate()
	if err != nil {
		return "", err
	}

	payloadHash, err := bcrypt.GenerateFromPassword(tokenPayload, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	record := &refreshTokenModel{
		ID:          NewRefreshTokenId(),
		PayloadHash: payloadHash,
		UserID:      userID,
		ClientID:    clientID,
	}

	if err := r.insert(record); err != nil {
		return "", err
	}

	return buildToken(record.ID, tokenPayload), nil
}

func (r *refreshTokenRepo) Verify(clientID, token string) (string, error) {
	tokenID, tokenPayload, err := parseToken(token)

	if err != nil {
		return "", err
	}

	record, err := r.get(tokenID)
	if err != nil {
		return "", err
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

	record, err := r.get(tokenID)
	if err != nil {
		return err
	}

	if record.UserID != userID {
		return refresh.ErrorInvalidUserID
	}

	if err := checkTokenPayload(record.PayloadHash, tokenPayload); err != nil {
		return err
	}

	_, err = r.driver.kAPI.Delete(context.Background(), r.key(record.ID), nil)
	return err
}

func (r *refreshTokenRepo) get(id string) (*refreshTokenModel, error) {
	kid := r.key(id)
	resp, err := r.driver.kAPI.Get(context.Background(), kid, nil)
	if err != nil {
		if cerr, ok := err.(etcdclient.Error); ok {
			if cerr.Code == etcdclient.ErrorCodeKeyNotFound {
				return nil, refresh.ErrorInvalidToken
			}
		}
		return nil, err
	}
	if resp == nil || resp.Node == nil {
		return nil, refresh.ErrorInvalidToken
	}
	var c refreshTokenModel
	err = json.Unmarshal([]byte(resp.Node.Value), &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *refreshTokenRepo) insert(rtm *refreshTokenModel) error {
	b, err := json.Marshal(rtm)
	if err != nil {
		return err
	}
	_, err = r.driver.kAPI.Create(context.Background(), r.key(rtm.ID), string(b))
	return err
}
