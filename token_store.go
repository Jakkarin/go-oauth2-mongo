package mongo

import (
	"context"
	"encoding/json"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TokenConfig token configuration parameters
type TokenConfig struct {
	// store txn collection name(The default is oauth2)
	TxnCName string
	// store token based data collection name(The default is oauth2_basic)
	BasicCName string
	// store access token data collection name(The default is oauth2_access)
	AccessCName string
	// store refresh token data collection name(The default is oauth2_refresh)
	RefreshCName string
}

// NewDefaultTokenConfig create a default token configuration
func NewDefaultTokenConfig() *TokenConfig {
	return &TokenConfig{
		TxnCName:     "oauth2_txn",
		BasicCName:   "oauth2_basic",
		AccessCName:  "oauth2_access",
		RefreshCName: "oauth2_refresh",
	}
}

// NewTokenStore create a token store instance based on mongodb
func NewTokenStore(cfg *Config, tcfgs ...*TokenConfig) (store *TokenStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.URL))

	if err != nil {
		panic(err)
	}

	return NewTokenStoreWithSession(client, cfg.DB, tcfgs...)
}

// NewTokenStoreWithSession create a token store instance based on mongodb
func NewTokenStoreWithSession(client *mongo.Client, dbName string, tcfgs ...*TokenConfig) *TokenStore {
	ts := &TokenStore{
		client: client,
		dbName: dbName,
		tcfg:   NewDefaultTokenConfig(),
	}

	if len(tcfgs) > 0 {
		ts.tcfg = tcfgs[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

	defer cancel()

	ts.col(ts.tcfg.BasicCName).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.M{
			"ExpiredAt": 1, // index in ascending order
		},
		Options: nil,
	})

	ts.col(ts.tcfg.AccessCName).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.M{
			"ExpiredAt": 1, // index in ascending order
		},
		Options: nil,
	})

	ts.col(ts.tcfg.RefreshCName).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.M{
			"ExpiredAt": 1, // index in ascending order
		},
		Options: nil,
	})

	return ts
}

// TokenStore MongoDB storage for OAuth 2.0
type TokenStore struct {
	tcfg   *TokenConfig
	dbName string
	client *mongo.Client
}

// Close the mongo connection
func (ts *TokenStore) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ts.client.Disconnect(ctx)
}

func (ts *TokenStore) col(name string) *mongo.Collection {
	return ts.client.Database(ts.dbName).Collection(name)
}

func (ts *TokenStore) dbHandler(fn func(context.Context, *mongo.Database) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	return ts.client.UseSession(ctx, func(session mongo.SessionContext) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

		defer cancel()

		session.StartTransaction()

		err := fn(ctx, session.Client().Database(ts.dbName))

		if err != nil {
			return session.AbortTransaction(ctx)
		}

		return session.CommitTransaction(ctx)
	})
}

func (ts *TokenStore) colHandler(name string, fn func(context.Context, *mongo.Collection) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	return ts.client.UseSession(ctx, func(session mongo.SessionContext) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

		defer cancel()

		session.StartTransaction()

		err := fn(ctx, ts.col(name))

		if err != nil {
			return session.AbortTransaction(ctx)
		}

		return session.CommitTransaction(ctx)
	})
}

// Create create and store the new token information
func (ts *TokenStore) Create(_ context.Context, info oauth2.TokenInfo) (err error) {
	jv, err := json.Marshal(info)

	if err != nil {
		return
	}

	if code := info.GetCode(); code != "" {
		return ts.colHandler(ts.tcfg.BasicCName, func(ctx context.Context, c *mongo.Collection) error {
			_, err := c.InsertOne(ctx, basicData{
				ID:        code,
				Data:      jv,
				ExpiredAt: info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()),
			})
			return err
		})
	}

	aexp := info.GetAccessCreateAt().Add(info.GetAccessExpiresIn())
	rexp := aexp

	if refresh := info.GetRefresh(); refresh != "" {
		rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn())
		if aexp.Second() > rexp.Second() {
			aexp = rexp
		}
	}

	// var payloads map[string]interface{}
	payloads := make(map[string]interface{})

	id := primitive.NewObjectID().Hex()

	payloads[ts.tcfg.BasicCName] = basicData{
		ID:        id,
		Data:      jv,
		ExpiredAt: rexp,
	}

	payloads[ts.tcfg.AccessCName] = tokenData{
		ID:        info.GetAccess(),
		BasicID:   id,
		ExpiredAt: aexp,
	}

	if refresh := info.GetRefresh(); refresh != "" {
		payloads[ts.tcfg.RefreshCName] = tokenData{
			ID:        refresh,
			BasicID:   id,
			ExpiredAt: rexp,
		}
	}

	return ts.dbHandler(func(ctx context.Context, d *mongo.Database) error {
		for key, value := range payloads {
			_, err := d.Collection(key).InsertOne(ctx, value)

			if err != nil {
				return err
			}
		}

		return nil
	})
}

// RemoveByCode use the authorization code to delete the token information
func (ts *TokenStore) RemoveByCode(_ context.Context, code string) error {
	return ts.colHandler(ts.tcfg.BasicCName, func(ctx context.Context, c *mongo.Collection) error {
		_, err := c.DeleteOne(ctx, bson.M{"_id": code})
		return err
	})
}

// RemoveByAccess use the access token to delete the token information
func (ts *TokenStore) RemoveByAccess(_ context.Context, access string) error {
	return ts.colHandler(ts.tcfg.AccessCName, func(ctx context.Context, c *mongo.Collection) error {
		_, err := c.DeleteOne(ctx, bson.M{"_id": access})
		return err
	})
}

// RemoveByRefresh use the refresh token to delete the token information
func (ts *TokenStore) RemoveByRefresh(_ context.Context, refresh string) error {
	return ts.colHandler(ts.tcfg.RefreshCName, func(ctx context.Context, c *mongo.Collection) error {
		_, err := c.DeleteOne(ctx, bson.M{"_id": refresh})
		return err
	})
}

func (ts *TokenStore) getData(basicID string) (oauth2.TokenInfo, error) {
	var tm models.Token

	err := ts.colHandler(ts.tcfg.BasicCName, func(ctx context.Context, c *mongo.Collection) error {
		var bd basicData
		err := c.FindOne(ctx, bson.M{"_id": basicID}).Decode(&bd)

		if err != nil {
			return err
		}

		return json.Unmarshal(bd.Data, &tm)
	})

	return &tm, err
}

func (ts *TokenStore) getBasicID(cname, token string) (string, error) {
	var basicID string

	err := ts.colHandler(cname, func(ctx context.Context, c *mongo.Collection) error {
		var td tokenData
		err := c.FindOne(ctx, bson.M{"_id": token}).Decode(&td)

		if err != nil {
			return err
		}

		basicID = td.BasicID
		return nil
	})

	return basicID, err
}

// GetByCode use the authorization code for token information data
func (ts *TokenStore) GetByCode(_ context.Context, code string) (oauth2.TokenInfo, error) {
	return ts.getData(code)
}

// GetByAccess use the access token for token information data
func (ts *TokenStore) GetByAccess(_ context.Context, access string) (oauth2.TokenInfo, error) {
	basicID, err := ts.getBasicID(ts.tcfg.AccessCName, access)

	if err != nil && basicID == "" {
		return nil, err
	}

	return ts.getData(basicID)
}

// GetByRefresh use the refresh token for token information data
func (ts *TokenStore) GetByRefresh(_ context.Context, refresh string) (oauth2.TokenInfo, error) {
	basicID, err := ts.getBasicID(ts.tcfg.RefreshCName, refresh)

	if err != nil && basicID == "" {
		return nil, err
	}

	return ts.getData(basicID)
}

type basicData struct {
	ID        string    `bson:"_id"`
	Data      []byte    `bson:"Data"`
	ExpiredAt time.Time `bson:"ExpiredAt"`
}

type tokenData struct {
	ID        string    `bson:"_id"`
	BasicID   string    `bson:"BasicID"`
	ExpiredAt time.Time `bson:"ExpiredAt"`
}
