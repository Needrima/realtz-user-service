package entity

type User struct {
	Reference             string `json:"reference" bson:"reference"`
	UserType              string `json:"user_type" bson:"user_type"`
	Firstname             string `json:"firstname" bson:"firstname"`
	Lastname              string `json:"lastname" bson:"lastname"`
	Fullname              string `json:"fullname" bson:"fullname"`
	Email                 string `json:"email" bson:"email"`
	PhoneNumber           string `json:"phone_number" bson:"phone_number"`
	BVN                   string `json:"-" bson:"bvn"`
	Password              string `json:"-" bson:"password"`
	IsEmailVerified       bool   `json:"is_email_verified" bson:"is_email_verified"`
	IsPhoneNumberVerified bool   `json:"is_phone_number_verified" bson:"is_phone_number_verified"`
	IsBvnVerified         bool   `json:"is_bvn_verified" bson:"is_bvn_verified"`
	IsVerified            bool   `json:"is_verified" bson:"is_verified"`
	IsActive              bool   `json:"is_active" bson:"is_active"`
	NumLikes              int    `json:"-" bson:"num_likes"`
	StarRating            int    `json:"-" bson:"star_rating"`
	CreatedOn             string `json:"created_on" bson:"created_on"`
	LastUpdatedOn         string `json:"last_updated_on" bson:"last_updated_on"`
}
