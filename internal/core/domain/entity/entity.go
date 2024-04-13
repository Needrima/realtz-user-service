package entity

type User struct {
	Reference             string   `json:"reference" bson:"reference"`
	UserType              string   `json:"user_type" bson:"user_type"`
	Firstname             string   `json:"firstname" bson:"firstname"`
	Lastname              string   `json:"lastname" bson:"lastname"`
	Fullname              string   `json:"fullname" bson:"fullname"`
	Username              string   `json:"username" bson:"username"`
	Email                 string   `json:"email" bson:"email"`
	Image                 string   `json:"image" bson:"image"`
	Bio                   string   `json:"bio" bson:"bio"`
	PhoneNumber           string   `json:"phone_number" bson:"phone_number"`
	BVN                   string   `json:"-" bson:"bvn"`
	Password              string   `json:"-" bson:"password"`
	IsEmailVerified       bool     `json:"is_email_verified" bson:"is_email_verified"`
	IsPhoneNumberVerified bool     `json:"is_phone_number_verified" bson:"is_phone_number_verified"`
	IsBvnVerified         bool     `json:"-" bson:"is_bvn_verified"`
	IsVerified            bool     `json:"is_verified" bson:"is_verified"`
	IsActive              bool     `json:"is_active" bson:"is_active"`
	NumLikes              int      `json:"num_likes" bson:"num_likes"`   // total number of likes on all users products (for agents only)
	NumSaves              int      `json:"num_saves" bson:"num_saves"`   // total number of products saved by user
	NumOrders             int      `json:"num_orders" bson:"num_orders"` // total number of orders
	StarRating            int      `json:"star_rating" bson:"star_rating"`
	RatedBy               []string `json:"rated_by" bson:"rated_by"` // array of references for people who rated the user
	NumProducts           int      `json:"num_products" bson:"num_products"`
	CreatedOn             string   `json:"created_on" bson:"created_on"`
	LastUpdatedOn         string   `json:"last_updated_on" bson:"last_updated_on"`
}
