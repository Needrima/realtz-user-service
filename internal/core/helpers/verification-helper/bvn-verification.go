package helpers

import (
// "bytes"
// "encoding/json"
// "io"
// "net/http"
// configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
// errorHelper "realtz-user-service/internal/core/helpers/error-helper"
// logHelper "realtz-user-service/internal/core/helpers/log-helper"
// "strings"
// "time"
)

func VerifyBvn(bvn, firstname, lastname, phoneNumber string) error {
	// body := map[string]interface{}{
	// 	"number": bvn,
	// }

	// jsonBody, err := json.Marshal(body)
	// if err != nil {
	// 	logHelper.LogEvent(logHelper.ErrorLog, "marshalling bvn verification request body: "+err.Error())
	// 	return errorHelper.NewServiceError("something went wrong", 500)
	// }

	// // Define the IdentityPass API endpoint
	// endpoint := configHelper.ServiceConfiguration.BVNVerificationEndpoint

	// // Create a POST request to the API endpoint
	// req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBody))
	// if err != nil {
	// 	logHelper.LogEvent(logHelper.ErrorLog, "error creating new bvn verification request: "+err.Error())
	// 	return errorHelper.NewServiceError("something went wrong", 500)
	// }

	// // Replace with your VerifyMe API key in app.env
	// apiKey := configHelper.ServiceConfiguration.IdentityPassAPIKey
	// appId := configHelper.ServiceConfiguration.IdentityPassAppId

	// // Set the necessary headers
	// req.Header.Set("x-api-key", apiKey)
	// req.Header.Set("app-id", appId)
	// req.Header.Set("Content-Type", "application/json")

	// // Create an HTTP client
	// client := &http.Client{
	// 	Timeout: time.Second * 20,
	// }

	// // Send the request
	// resp, err := client.Do(req)
	// if err != nil {
	// 	logHelper.LogEvent(logHelper.ErrorLog, "error sending bvn verification request: "+err.Error())
	// 	return errorHelper.NewServiceError("something went wrong", 500)
	// }

	// defer resp.Body.Close()

	// // Read the response body
	// responseBody, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	logHelper.LogEvent(logHelper.ErrorLog, "error reading bvn verification response body: "+err.Error())
	// 	return errorHelper.NewServiceError("something went wrong", 500)
	// }

	// respData := map[string]interface{}{}

	// if err := json.Unmarshal(responseBody, &respData); err != nil {
	// 	logHelper.LogEvent(logHelper.ErrorLog, "error unmarshalling bvn verification response body: "+err.Error())
	// 	return errorHelper.NewServiceError("something went wrong", 500)
	// }

	// // respData looks like this
	// // {
	// // 	"status": true,
	// // 	"detail": "Verification Successfull",
	// // 	"response_code": "00",
	// // 	"data": {
	// // 		"firstName": "John",
	// // 		"middleName": "Doe",
	// // 		"lastName": "Jane",
	// // 		"dateOfBirth": "01-Jan-2000",
	// // 		"phoneNumber": "08012345678"
	// // 	},
	// // 	"source": "API",
	// // 	"user_info": null,
	// // 	"request_data": {
	// // 		"number": "54651333604"
	// // 	}
	// // }

	// // use data below for confidence check

	// userData := respData["data"].(map[string]interface{})

	// // check if firstname correlates with data from identity verification
	// bvnFirstName := userData["firstName"].(string)
	// if !strings.EqualFold(bvnFirstName, firstname) {
	// 	logHelper.LogEvent(logHelper.ErrorLog, "firstname does not tally with firstname from bvn: "+err.Error())
	// 	return errorHelper.NewServiceError("bvn does not tally with user information", 400)
	// }

	// // check if firstname correlates with data from identity verification
	// bvnLastName := userData["lastName"].(string)
	// if !strings.EqualFold(bvnLastName, lastname) {
	// 	logHelper.LogEvent(logHelper.ErrorLog, "lastname does not tally with lastname from bvn: "+err.Error())
	// 	return errorHelper.NewServiceError("bvn does not tally with user information", 400)
	// }

	// // check if phonenumber correlates with data from identity verification
	// bvnPhoneNumber := userData["phoneNumber"].(string)
	// bvnPhoneNumber = "0" + bvnPhoneNumber[3:] // trim +234 from phone number and append "0" to it
	// if !strings.EqualFold(bvnPhoneNumber, phoneNumber) {
	// 	logHelper.LogEvent(logHelper.ErrorLog, "phone number does not tally with phone number from bvn: "+err.Error())
	// 	return errorHelper.NewServiceError("bvn does not tally with user information", 400)
	// }

	return nil
}
