package etcd

import (
	"encoding/json"
	"errors"
	"github.com/coreos/dex/connector"
	"github.com/coreos/dex/repo"
	"github.com/coreos/dex/user"
	etcdclient "github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"path"
)

func newConnectorConfigModel(cfg connector.ConnectorConfig) (*connectorConfigModel, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	m := &connectorConfigModel{
		ID:     cfg.ConnectorID(),
		Type:   cfg.ConnectorType(),
		Config: string(b),
	}

	return m, nil
}

type connectorConfigModel struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Config string `json:"config"`
}

func (m *connectorConfigModel) ConnectorConfig() (connector.ConnectorConfig, error) {
	cfg, err := connector.NewConnectorConfigFromType(m.Type)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal([]byte(m.Config), cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func NewConnectorConfigRepo(driver *EtcdDriver) *connectorConfigRepo {
	return &connectorConfigRepo{driver: driver}
}

type connectorConfigRepo struct {
	driver *EtcdDriver
}

func (r *connectorConfigRepo) dir() string {
	return path.Join(r.driver.directory, ConnectorConfigDirectory)
}

func (r *connectorConfigRepo) key(id string) string {
	return path.Join(r.driver.directory, ConnectorConfigDirectory, id)
}

func (r *connectorConfigRepo) All() ([]connector.ConnectorConfig, error) {
	resp, err := r.driver.kAPI.Get(context.Background(), r.dir(), &etcdclient.GetOptions{Recursive: true})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Node == nil {
		return nil, user.ErrorNotFound
	}
	if !resp.Node.Dir {
		return nil, errors.New("node is not directory")
	}
	var cfgs []connector.ConnectorConfig
	for _, n := range resp.Node.Nodes {
		if n.Value != "" {
			var c connectorConfigModel
			err = json.Unmarshal([]byte(n.Value), &c)
			if err != nil {
				return nil, err
			}
			cc, err := c.ConnectorConfig()
			if err != nil {
				return nil, err
			}
			cfgs = append(cfgs, cc)
		}
	}
	return cfgs, nil
}

func (r *connectorConfigRepo) GetConnectorByID(tx repo.Transaction, id string) (connector.ConnectorConfig, error) {
	kid := r.key(id)
	resp, err := r.driver.kAPI.Get(context.Background(), kid, nil)

	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Node == nil {
		return nil, connector.ErrorNotFound
	}
	var c connectorConfigModel
	err = json.Unmarshal([]byte(resp.Node.Value), &c)
	if err != nil {
		return nil, err
	}
	return c.ConnectorConfig()
}

func (r *connectorConfigRepo) Set(cfgs []connector.ConnectorConfig) error {
	api := r.driver.kAPI
	for _, cfg := range cfgs {
		m, err := newConnectorConfigModel(cfg)
		if err != nil {
			return err
		}
		b, err := json.Marshal(m)
		if err != nil {
			return err
		}
		_, err = api.Create(context.Background(), r.key(m.ID), string(b))
		if err != nil {
			return err
		}
	}
	return nil
}
