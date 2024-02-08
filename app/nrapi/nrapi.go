package nrapi

import (
	"fmt"
	"io"
	"net/http"
	"os"

	newrelic "github.com/newrelic/go-agent/v3/newrelic"
)

var (
	App, _ = newrelic.NewApplication(
		newrelic.ConfigAppName(fmt.Sprintf("WG OAuth Portal %s", os.Getenv("ENVIRONMENT"))),
		newrelic.ConfigLicense(os.Getenv("NRLICENSE")),
	)
)

func init() {
	if os.Getenv("NRLICENSE") == "" {
		fmt.Println("Couldn't initialize NR")
	}
}

func NrWebRequest(txn *newrelic.Transaction, client *http.Client, method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	segment := newrelic.StartExternalSegment(txn, req)
	defer segment.End()
	response, err := client.Do(req)
	return response, err
}
