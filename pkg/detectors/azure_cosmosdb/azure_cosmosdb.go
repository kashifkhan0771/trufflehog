package azure_cosmosdb

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

var (
	defaultClient = common.SaneHttpClient()

	dbKeyPattern = regexp.MustCompile(`([A-Za-z0-9+/=]{88})`)
	// account name can contain only lowercase letters, numbers and the `-` character, must be between 3 and 44 characters long.
	accountUrlPattern = regexp.MustCompile(`(https://[a-z0-9-]{3,44}.documents\.azure\.com:[0-9]{3})`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureCosmosDB
}

func (s Scanner) Description() string {
	return "Azure Cosmos DB is a globally distributed, multi-model database service offered by Microsoft. CosmosDB keys and connection string are used to connect with Cosmos DB."
}

func (s Scanner) Keywords() []string {
	return []string{"cosmos", ".documents.azure.com"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeyMatches, uniqueAccountMatches = make(map[string]struct{}), make(map[string]struct{})

	for _, match := range dbKeyPattern.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[match[1]] = struct{}{}
	}

	for _, match := range accountUrlPattern.FindAllStringSubmatch(dataStr, -1) {
		uniqueAccountMatches[match[1]] = struct{}{}
	}

	for key := range uniqueKeyMatches {
		for accountUrl := range uniqueAccountMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureCosmosDB,
				Raw:          []byte(key),
				ExtraData:    make(map[string]string),
			}

			if verify {
				verified, verificationErr := verifyCosmosDB(s.getClient(), accountUrl, key)
				s1.Verified = verified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

// documentation: https://learn.microsoft.com/en-us/rest/api/cosmos-db/list-databases
func verifyCosmosDB(client *http.Client, accountUrl, key string) (bool, error) {
	// decode the base64 encoded key
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false, fmt.Errorf("failed to decode key: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/dbs", accountUrl), nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %v", err)
	}

	dateRFC1123 := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	authHeader := fmt.Sprintf("type=master&ver=1.0&sig=%s", url.QueryEscape(createSignature(decodedKey, dateRFC1123)))

	// required headers
	// docs: https://learn.microsoft.com/en-us/rest/api/cosmos-db/common-cosmosdb-rest-request-headers
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("x-ms-date", dateRFC1123)
	req.Header.Set("x-ms-version", "2018-12-31")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %v", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Check response status code
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func createSignature(decodedKey []byte, dateRFC1123 string) string {
	stringToSign := fmt.Sprintf(
		"%s\n%s\n%s\n%s\n\n",
		strings.ToLower(http.MethodGet),
		strings.ToLower("dbs"),
		"",
		strings.ToLower(dateRFC1123),
	)

	// compute HMAC-SHA256 signature
	mac := hmac.New(sha256.New, decodedKey)
	mac.Write([]byte(stringToSign))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
