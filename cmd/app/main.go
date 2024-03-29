package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/ardimr/go-authentication-service.git/configs/db"
	"github.com/ardimr/go-authentication-service.git/configs/redis"
	"github.com/ardimr/go-authentication-service.git/internal/auth"
	"github.com/ardimr/go-authentication-service.git/internal/controller"
	"github.com/ardimr/go-authentication-service.git/internal/query"
	router "github.com/ardimr/go-authentication-service.git/internal/routes"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	log.Println("Running App1")

	// Load .env
	godotenv.Load(".env")

	// Create new DB
	dbConnection, err := db.NewDB(
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	if err != nil {
		log.Fatalln(err.Error())
		return
	} else {
		log.Println("Connected to DB")
	}
	defer dbConnection.Close()

	// Setup Redis client
	redisHost := os.Getenv("REDIS_HOST")
	redisPassword := os.Getenv("REDIS_PASSWORD")
	redisDB, _ := strconv.Atoi(os.Getenv("REDIS_DB"))

	_, err = redis.NewRedisClient(
		redisHost,
		redisPassword,
		redisDB,
	)

	if err != nil {
		log.Println("Failed to connect redis")
	}

	// Setup Cloud Storage
	// var cloudClient cloudstorage.CloudStorageInterface

	// cloudStorageUseSSL, err := strconv.ParseBool(os.Getenv("CLOUD_STORAGE_USE_SSL"))
	// if err != nil {
	// 	log.Println(err.Error())
	// }

	// minioClient, err := cloudstorage.NewMinioClient(
	// 	os.Getenv("CLOUD_STORAGE_ENDPOINT"),
	// 	os.Getenv("CLOUD_STORAGE_ACCESS_KEY"),
	// 	os.Getenv("CLOUD_STORAGE_SECRET_KEY"),
	// 	cloudStorageUseSSL,
	// )
	// if err != nil {
	// 	log.Println(err)
	// }

	// Use minio as cloud client
	// cloudClient = minioClient

	// cloudClient.ListBuckets(context.Background())
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:3000"}
	corsConfig.AllowCredentials = true
	corsConfig.AllowHeaders = append(corsConfig.AllowHeaders, "Authorization")
	fmt.Println(corsConfig)
	// Setup REST Server
	restServer := gin.New()
	restServer.Use(gin.Recovery())
	restServer.Use(gin.Logger())
	restServer.Use(gzip.Gzip(gzip.DefaultCompression))
	restServer.Use(cors.New(corsConfig))

	// Initialize Auth service
	expiresAt, err := strconv.Atoi(os.Getenv("JWT_EXPIRES_AT"))

	if err != nil {
		log.Println(err.Error())
	}
	log.Println(expiresAt)
	auth := auth.NewAuthService(
		os.Getenv("JWT_ISSUER"),
		int64(expiresAt),
		[]byte(os.Getenv("JWT_SIGNING_KEY")),
		query.NewPostgresQuerier(dbConnection),
	)

	// Setup Router
	userController := controller.NewController(query.NewPostgresQuerier(dbConnection), auth)
	// authController := controller.NewController(query.NewPostgresQuerier(dbConnection))

	userRouter := router.NewRouter(userController, auth)
	// authRouter := router.NewRouter(authController)

	userRouter.AddRoute(restServer.Group("/api"))

	// Run server
	restServer.Run("localhost:8080")

}
