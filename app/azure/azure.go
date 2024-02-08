package azure

// azure oauth2-specific auth code

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sidecar/logger"
	"time"
	"wg-oauth/confs"
	"wg-oauth/structs"

	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

var (
	cookieKey = os.Getenv("WG_COOKIE_KEY")
)

func HandleAzureLogin(w http.ResponseWriter, r *http.Request) {
	authURL := confs.OAuthConf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		logger.Logger.Error("No callback code from OAuth")
		return
	}
	token, err := confs.OAuthConf.Exchange(r.Context(), code)
	if err != nil {
		logger.Logger.Error(fmt.Sprintf("Failed to get token: %v", err))
		return
	}
	isMember, isAdmin, err := GetUserGroups(token.AccessToken)
	if err != nil {
		logger.Logger.Warn(fmt.Sprintf("Error validating group membership: %v", err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	} else if isMember == false {
		logger.Logger.Warn("Invalid user -- could not validate group membership")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	} else if isMember == true {
		userName, email, err := GetUserInfo(token.AccessToken)
		if err != nil {
			logger.Logger.Error(fmt.Sprintf("Error logging in: %v", err))
			return
		}
		logger.Logger.Info(fmt.Sprintf("%v logged in", userName))
		expires := time.Now().Add(168 * time.Hour)
		userCookie := &structs.UserCookie{
			Username: userName,
			IsAdmin:  isAdmin,
			Expires:  expires,
			Email:    email,
		}
		encodedValue, err := securecookie.EncodeMulti("userCookie", userCookie, securecookie.CodecsFromPairs([]byte(cookieKey))...)
		if err != nil {
			http.Error(w, "Error encoding cookie", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:   "userCookie",
			Value:  encodedValue,
			Path:   "/",
			MaxAge: 168 * 60 * 60,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
}

func checkGroup(accessToken string, url string, targetGroupID string) (bool, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	for _, group := range result.Value {
		if group.ID == targetGroupID {
			return true, nil
		}
	}
	return false, nil
}

func GetUserGroups(accessToken string) (bool, bool, error) {
	isMember, err := checkGroup(accessToken, "https://graph.microsoft.com/v1.0/me/memberOf", os.Getenv("WG_GROUP_MEMBER"))
	if err != nil {
		return false, false, err
	}
	isOwner, err := checkGroup(accessToken, "https://graph.microsoft.com/v1.0/me/ownedObjects", os.Getenv("WG_GROUP_MEMBER"))
	if err != nil {
		return false, false, err
	}
	return isMember, isOwner, nil
}

func GetUserInfo(accessToken string) (string, string, error) {
	url := "https://graph.microsoft.com/v1.0/me"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var result struct {
		GivenName   string `json:"givenName"`
		Surname     string `json:"surname"`
		DisplayName string `json:"displayName"`
		Email       string `json:"mail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}
	if result.Email == "" {
		result.Email = result.UserPrincipalName // fallback
	}
	if result.Email == "" {
		return "", "", fmt.Errorf(fmt.Sprintf("No email for %v", result.DisplayName))
	}
	return result.DisplayName, result.Email, nil
}
