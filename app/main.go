package main

import (
    "fmt"
    "net/http"
    "os"
    "wg-oauth/logger"
    "wg-oauth/wgapi"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var wgManager *wgapi.WireGuardManager

func init() {
	var err error
    wgManager, err = wgapi.NewWireGuardManager("wg0")
    if err != nil {
        logger.Logger.Error(fmt.Sprintf("Failed to initialize WireGuard manager: %v", err))
        os.Exit(1)
    }
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
    userEmail := "user@example.com"
    userPubKey := findUserPubKeyByEmail(userEmail)
    if userPubKey == "" {
        fmt.Fprintf(w, "User public key not found")
        return
    }
    err := wgManager.UpdatePeerRules(userPubKey, true)
    if err != nil {
        logger.Logger.Error(fmt.Sprintf("Failed to update peer rules for %s: %v", userEmail, err))
        http.Error(w, "Failed to update network access", http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "Network access updated for %s", userEmail)
}

func findUserPubKeyByEmail(email string) string {
    userDB := map[string]string{
        "user@example.com": "userPublicKeyHere",
    }
    return userDB[email]
}

func main() {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Logger.Info(fmt.Sprintf("Failed to generate private key: %v\n", err))
		return
	}
	publicKey := privateKey.PublicKey()
	logger.Logger.Info(fmt.Sprintf("Adding %s", publicKey.String()))
	if err = wgManager.AddPeer(wgtypes.PeerConfig{PublicKey: publicKey}); err != nil {
		logger.Logger.Error(fmt.Sprintf("Couldn't add peer %v: %w", publicKey, err))
	}
	if err = wgManager.UpdatePeerRules(publicKey.String(), true); err != nil {
		logger.Logger.Error(fmt.Sprintf("Couldn't update peer rules %v: %w", publicKey, err))
	}
    http.HandleFunc("/oauth/callback", handleOAuthCallback)
    logger.Logger.Info("Starting server on :8080...")
    http.ListenAndServe(":8080", nil)
}
