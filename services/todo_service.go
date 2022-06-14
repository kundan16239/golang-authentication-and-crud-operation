package services

import (
	"context"
	"fiber-mongo-api/configs"
	"fiber-mongo-api/models"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
var productCollection *mongo.Collection = configs.GetCollection(configs.DB, "products")

func Postuser(user models.User) (models.User, error) {
	res, err := userCollection.InsertOne(context.Background(), user)
	if err != nil {
		log.Fatal(err)
		return models.User{}, err
	}
	fmt.Println(res.InsertedID)
	return user, nil
}

func Getemail(email string) (models.User, error) {
	var user models.User
	err := userCollection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		log.Fatal(err)
		return user, err
	}
	return user, nil
}
