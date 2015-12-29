package mongodb

import (
	"encoding/json"
	"github.com/coreos/dex/connector"
	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/dex/repo"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/mgo.v2"
)

type connectorConfigs struct {
	driver *MongoDBDriver
}

type connectorConfigModel struct {
	ID     string `bson:"connectorID"`
	Type   string `bson:"type"`
	Config string `bson:"config"`
}

func (c *connectorConfigModel) ConnectorConfig() (connector.ConnectorConfig, error) {
	cfg, err := connector.NewConnectorConfigFromType(c.Type)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal([]byte(c.Config), cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func newConnectorConfigModel(cfg connector.ConnectorConfig) (connectorConfigModel, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return connectorConfigModel{}, err
	}
	m := connectorConfigModel{
		ID:     cfg.ConnectorID(),
		Type:   cfg.ConnectorType(),
		Config: string(b),
	}
	return m, nil
}

func (c *connectorConfigs) All() ([]connector.ConnectorConfig, error) {
	col := c.driver.Session.DB("").C(ConnectorCollection)
	var all []*connectorConfigModel
	col.Find(nil).All(&all)

	result := make([]connector.ConnectorConfig, len(all))
	for i, m := range all {
		cfg, err := m.ConnectorConfig()
		if err != nil {
			return nil, err
		}
		result[i] = cfg
	}
	return result, nil
}

func (c *connectorConfigs) Set(cfgs []connector.ConnectorConfig) error {
	col := c.driver.Session.DB("").C(ConnectorCollection)
	col.DropCollection()
	bulk := col.Bulk()

	for _, cfg := range cfgs {
		m, err := newConnectorConfigModel(cfg)
		if err != nil {
			log.Errorf("mongodb/connector.go: error during creating model: %v", err)
			return err
		}
		bulk.Insert(m)
	}

	res, err := bulk.Run()

	if err != nil {
		log.Errorf("mongodb/connector.go: Bulk insert [error]:%v\n[result]:%v", err, res)
	}
	return err
}

func (c *connectorConfigs)GetConnectorByID(tr repo.Transaction, id string) (connector.ConnectorConfig, error) {
	col := c.driver.Session.DB("").C(ConnectorCollection)
	var cc connectorConfigModel
	err := col.Find(bson.M{"connectorID":id}).One(&cc)
	if err == mgo.ErrNotFound {
		return nil, connector.ErrorNotFound
	}
	if err != nil {
		return nil, err
	}
	return cc.ConnectorConfig()
}
