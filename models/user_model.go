package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	Id       primitive.ObjectID `json:"id" bson:"_id"`
	Email    string             `json:"email" bson:"email"`
	Password string             `json:"password" bson:"password"`
}

type Product struct {
	Id                   primitive.ObjectID `json:"id,omitempty" bson:"_id"`
	Product_Name         string             `json:"name,omitempty" validate:"required"`
	Product_Category     string             `json:"product_category,omitempty" validate:"required"`
	Product_Sub_Category string             `json:"product_sub_category,omitempty" validate:"required"`
	Description          string             `json:"description,omitempty" validate:"required"`
	Price                string             `json:"price,omitempty" validate:"required"`
	Discount             string             `json:"discount,omitempty" validate:"required"`
	UserId               string             `json:"userid,omitempty" validate:"required"`
}
