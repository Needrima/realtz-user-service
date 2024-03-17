package helpers

import (
	"log"

	"github.com/spf13/viper"
)

type Configuration struct {
	ServiceName               string `mapstructure:"Service_Name"`
	ServiceHost               string `mapstructure:"Service_Host"`
	ServicePort               string `mapstructure:"Service_Port"`
	MongoDBConnString         string `mapstructure:"MongoDB_Connection_String"`
	MongoDbDatabaseName       string `mapstructure:"MongoDB_Database_Name"`
	MongoDBUserCollectionName string `mapstructure:"MongoDB_User_Collection_Name"`
	RedisConnString           string `mapstructure:"Redis_Connection_String"`
	RedisConnPassword         string `mapstructure:"Redis_Connection_Password"`
	LogDir                    string `mapstructure:"Log_Dir"`
	LogFile                   string `mapstructure:"Log_File"`
	JWTTokenKey               string `mapstructure:"JWT_Token_Key"`
	OtpExpiry                 string `mapstructure:"Otp_Expiry"`
	RedisRevokedTokensKey     string `mapstructure:"Redis_Revoked_Tokens_Key"`
	BVNVerificationEndpoint   string `mapstructure:"BVN_Verification_Endpoint"`
	IdentityPassAPIKey        string `mapstructure:"IdentityPass_API_Key"`
	IdentityPassAppId         string `mapstructure:"IdentityPass_App_ID"`
}

var ServiceConfiguration = loadConfig(".")

func loadConfig(path string) Configuration {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("read in config:", err)
	}

	var config Configuration
	err = viper.Unmarshal(&config)
	if err != nil {
		log.Fatal("unmarsal in config:", err)
	}

	return config
}
