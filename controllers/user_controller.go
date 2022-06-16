package controllers

import (
	"context"
	"errors"
	"fiber-mongo-api/configs"
	"fiber-mongo-api/models"
	"fiber-mongo-api/responses"

	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/form3tech-oss/jwt-go"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
var productCollection *mongo.Collection = configs.GetCollection(configs.DB, "products")
var validate = validator.New()

var (
	JwtSecretKey     = []byte(os.Getenv("JWT_SECRET_KEY"))
	JwtSigningMethod = jwt.SigningMethodHS256.Name
)

func NewToken(userId string) (string, error) {
	claims := jwt.StandardClaims{
		Id:        userId,
		Issuer:    userId,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 30).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecretKey)
}

func validateSignedMethod(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}
	return JwtSecretKey, nil
}

func ParseToken(tokenString string) (*jwt.StandardClaims, error) {
	claims := new(jwt.StandardClaims)
	token, err := jwt.ParseWithClaims(tokenString, claims, validateSignedMethod)
	if err != nil {
		return nil, err
	}
	var ok bool
	claims, ok = token.Claims.(*jwt.StandardClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid auth-token")
	}
	return claims, nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func VerifyPassword(hashed, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
}

func Register(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var user models.User
	defer cancel()
	// user := new(user)
	//validate the request body
	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	//use the validator library to validate required fields
	if validationErr := validate.Struct(&user); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": validationErr.Error()}})
	}
	hash, err := hashPassword(user.Password)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Couldn't hash password", "data": err})

	}
	// createdRecord := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&user)
	// fmt.Println(user.Email)
	filterCursor, err := userCollection.Find(c.Context(), bson.M{"email": user.Email})
	if err != nil {
		log.Fatal(err)
	}
	var userEmail []bson.M
	if err = filterCursor.All(c.Context(), &userEmail); err != nil {
		log.Fatal(err)
	}
	fmt.Println(userEmail)
	if userEmail != nil {
		return c.Status(400).JSON(fiber.Map{"message": "User Already Exist"})
	}
	user.Password = hash
	newUser := models.User{
		Id:       primitive.NewObjectID(),
		Email:    user.Email,
		Password: hash,
	}
	result, err := userCollection.InsertOne(ctx, newUser)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}
	filter := bson.D{{Key: "_id", Value: result.InsertedID}}
	createdRecord := userCollection.FindOne(c.Context(), filter)

	// decode the Mongo record into Employee
	createdUser := &models.User{}
	createdRecord.Decode(createdUser)

	// return the created Employee in JSON format
	// return c.Status(201).JSON(createdUser)
	return c.Status(http.StatusCreated).JSON(responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: &fiber.Map{"data": createdUser}})

	// filter := bson.D{{key: "_id", value: result.InsertedID}}
	// value := result.InsertedID
	// objId, _ := primitive.ObjectIDFromHex(value)
	// createdRecord := userCollection.FindOne(ctx, bson.M{"Email": user.Email}).Decode(&user)

}

func Login(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var input models.User
	var user models.User
	defer cancel()
	err := c.BodyParser(&input)
	if err != nil {
		return c.
			Status(http.StatusUnprocessableEntity).SendString("No details enter")
	}
	// var result bson.D
	// filter := bson.D{{"email", input.Email}}
	// err := userCollection.FindOne(ctx, filter).Decode(&result)
	// exist := userCollection.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user)
	// fmt.Println(exist)
	// fmt.Println(user.Email)
	filterCursor, err := userCollection.Find(c.Context(), bson.M{"email": input.Email})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(filterCursor)
	var exist []bson.M
	if err = filterCursor.All(ctx, &exist); err != nil {
		log.Fatal(err)
	}
	fmt.Println(exist)
	// if exist == nil {
	// 	return c.Status(400).JSON(fiber.Map{"message": "User Already Exist"})
	// }
	// fmt.Println(result)

	if exist == nil {
		// log.Printf("%s signin failed: %v\n", input.Email, err.Error())
		return c.Status(http.StatusUnauthorized).SendString("Unauthorized")
	}
	out := exist[0]
	userPassword := out["password"].(string)

	fmt.Println(userPassword)
	err = VerifyPassword(userPassword, input.Password)
	if err != nil {
		log.Printf("%s signin failed: %v\n", input.Email, err.Error())
		return c.
			Status(http.StatusUnauthorized).SendString("Unauthorized")
	}
	token, err := NewToken(user.Id.Hex())
	if err != nil {
		log.Printf("%s signin failed: %v\n", input.Email, err.Error())
		return c.
			Status(http.StatusUnauthorized).SendString("Unauthorized")
	}
	return c.
		Status(http.StatusOK).
		JSON(fiber.Map{
			"user":  out,
			"token": fmt.Sprintf("Bearer %s", token),
		})
}
