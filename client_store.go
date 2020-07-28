package mongo

import (
	"context"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ClientConfig client configuration parameters
type ClientConfig struct {
	// store clients data collection name(The default is oauth2_clients)
	ClientsCName string
}

// ClientStore MongoDB storage for OAuth 2.0
type ClientStore struct {
	ccfg   *ClientConfig
	dbName string
	client *mongo.Client
}

type client struct {
	ID     string `bson:"_id"`
	Secret string `bson:"secret"`
	Domain string `bson:"domain"`
	UserID string `bson:"userid"`
}

// NewDefaultClientConfig create a default client configuration
func NewDefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ClientsCName: "oauth2_clients",
	}
}

// NewClientStore create a client store instance based on mongodb
func NewClientStore(cfg *Config, ccfgs ...*ClientConfig) *ClientStore {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.URL))

	if err != nil {
		panic(err)
	}

	return NewClientStoreWithSession(client, cfg.DB, ccfgs...)
}

// NewClientStoreWithSession create a client store instance based on mongodb
func NewClientStoreWithSession(client *mongo.Client, dbName string, ccfgs ...*ClientConfig) *ClientStore {
	cs := &ClientStore{
		dbName: dbName,
		client: client,
		ccfg:   NewDefaultClientConfig(),
	}

	if len(ccfgs) > 0 {
		cs.ccfg = ccfgs[0]
	}

	return cs
}

// Close close the mongo session
func (cs *ClientStore) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cs.client.Disconnect(ctx)
}

func (cs *ClientStore) col(name string) *mongo.Collection {
	return cs.client.Database(cs.dbName).Collection(name)
}

func (cs *ClientStore) colHandler(name string, fn func(context.Context, *mongo.Collection) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	return cs.client.UseSession(ctx, func(session mongo.SessionContext) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

		defer cancel()

		session.StartTransaction()

		err := fn(ctx, cs.col(name))

		if err != nil {
			return session.AbortTransaction(ctx)
		}

		return session.CommitTransaction(ctx)
	})
}

// Set set client information
func (cs *ClientStore) Set(info oauth2.ClientInfo) error {
	return cs.colHandler(cs.ccfg.ClientsCName, func(ctx context.Context, c *mongo.Collection) error {
		entity := &client{
			ID:     info.GetID(),
			Secret: info.GetSecret(),
			Domain: info.GetDomain(),
			UserID: info.GetUserID(),
		}

		_, err := c.InsertOne(ctx, entity)
		return err
	})
}

// GetByID according to the ID for the client information
func (cs *ClientStore) GetByID(_ context.Context, id string) (oauth2.ClientInfo, error) {
	var info *models.Client

	err := cs.colHandler(cs.ccfg.ClientsCName, func(ctx context.Context, c *mongo.Collection) error {
		entity := new(client)

		err := c.FindOne(ctx, bson.M{"_id": id}).Decode(entity)

		if err != nil {
			return err
		}

		info = &models.Client{
			ID:     entity.ID,
			Secret: entity.Secret,
			Domain: entity.Domain,
			UserID: entity.UserID,
		}

		return nil
	})

	return info, err
}

// RemoveByID use the client id to delete the client information
func (cs *ClientStore) RemoveByID(id string) error {
	return cs.colHandler(cs.ccfg.ClientsCName, func(ctx context.Context, c *mongo.Collection) error {
		_, err := c.DeleteOne(ctx, bson.M{"_id": id})
		return err
	})
}
