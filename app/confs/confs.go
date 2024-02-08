package confs

import (
	"os"

	"golang.org/x/oauth2"
)

var (
	clientId     = os.Getenv("WG_AZURE_ID")
	clientSecret = os.Getenv("WG_AZURE_SECRET")
	redirectUrl  = os.Getenv("WG_REDIRECT")
	OAuthConf    = &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  redirectUrl,
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/43f7294c-1d27-4a9b-bf47-619a93b325a6/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/43f7294c-1d27-4a9b-bf47-619a93b325a6/oauth2/v2.0/token",
		},
	}
)
