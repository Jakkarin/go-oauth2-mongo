# Mongo Storage for [OAuth 2.0](https://github.com/go-oauth2/oauth2) (*Temporary)

## Note

- Wait of official <https://github.com/go-oauth2/mongo> update to V4

## Usage

``` go
package main

import (
	store "your-package/mongo"
)

func main() {
	manager := manage.NewDefaultManager()

	config := &mongo.Config{
		URL: "mongodb+srv://ex01:<password>@cluster0.0zkpo.gcp.mongodb.net/<dbname>?retryWrites=true&w=majority",
		DB:  "oauth2",
	}

	// use mongodb token store
	tokenStore := store.NewTokenStore(config)
	manager.MapTokenStorage(tokenStore, nil)

	// use mongodb client store
	clientStore := mongo.NewClientStore(config)
	manager.MapClientStorage(clientStore)

	// ...
}
```

## MIT License

```
Copyright (c) 2016 Lyric
```
