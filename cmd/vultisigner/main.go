package main

import (
	"fmt"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/plugin/api"
	"github.com/vultisig/plugin/config"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/plugin/storage/postgres"
)

func main() {
	cfg, err := config.GetConfigure()
	if err != nil {
		panic(err)
	}

	logger := logrus.New()

	sdClient, err := statsd.New(fmt.Sprintf("%s:%s", cfg.Datadog.Host, cfg.Datadog.Port))
	if err != nil {
		panic(err)
	}

	redisStorage, err := storage.NewRedisStorage(*cfg)
	if err != nil {
		panic(err)
	}

	redisOptions := asynq.RedisClientOpt{
		Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
		Username: cfg.Redis.User,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	client := asynq.NewClient(redisOptions)
	defer func() {
		if err := client.Close(); err != nil {
			fmt.Println("fail to close asynq client,", err)
		}
	}()

	inspector := asynq.NewInspector(redisOptions)
	if cfg.Server.VaultsFilePath == "" {
		panic("vaults file path is empty")

	}
	vaultStorage, err := vault.NewBlockStorageImp(cfg.BlockStorage)
	if err != nil {
		panic(err)
	}

	db, err := postgres.NewPostgresBackend(cfg.Server.Database.DSN)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}

	server := api.NewServer(
		cfg,
		db,
		redisStorage,
		vaultStorage,
		redisOptions,
		client,
		inspector,
		sdClient,
		cfg.Server.VaultsFilePath,
		cfg.Server.Mode,
		cfg.Server.Plugin.Type,
		logger,
	)
	if err := server.StartServer(); err != nil {
		panic(err)
	}
}
