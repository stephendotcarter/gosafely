package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dchest/pbkdf2"
	"golang.org/x/crypto/openpgp"
)

var (
	URLAPIPrefix         = "/api/v2.0"
	URLVerifyCredentials = "/config/verify-credentials/"
	DownloadAPI          = "JAVA_API"
	APIKeyHeader         = "ss-api-key"
	TimestampHeader      = "ss-request-timestamp"
	SignatureHeader      = "ss-request-signature"
	ContentType          = "application/json"
)

type API struct {
	host      string
	apiKey    string
	apiSecret string
}

type UserInformation struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	ClientKey   string `json:"clientKey"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	BetaUser    bool   `json:"betaUser"`
	AdminUser   bool   `json:"adminUser"`
	PublicKey   bool   `json:"publicKey"`
	PackageLife int    `json:"packageLife"`
	Response    string `json:"response"`
}

type Package struct {
	PackageID    string `json:"packageId"`
	PackageCode  string `json:"packageCode"`
	ServerSecret string `json:"serverSecret"`
	Recipients   []struct {
		RecipientID        string        `json:"recipientId"`
		Email              string        `json:"email"`
		FullName           string        `json:"fullName"`
		NeedsApproval      bool          `json:"needsApproval"`
		RecipientCode      string        `json:"recipientCode"`
		Confirmations      []interface{} `json:"confirmations"`
		IsPackageOwner     bool          `json:"isPackageOwner"`
		CheckForPublicKeys bool          `json:"checkForPublicKeys"`
		RoleName           string        `json:"roleName"`
	} `json:"recipients"`
	ContactGroups []struct {
		ContactGroupID                  string `json:"contactGroupId"`
		ContactGroupName                string `json:"contactGroupName"`
		ContactGroupIsOrganizationGroup bool   `json:"contactGroupIsOrganizationGroup"`
		Users                           []struct {
			UserEmail string `json:"userEmail"`
			UserID    string `json:"userId"`
		} `json:"users"`
	} `json:"contactGroups"`
	Files            []File        `json:"files"`
	Directories      []interface{} `json:"directories"`
	ApproverList     []interface{} `json:"approverList"`
	NeedsApproval    bool          `json:"needsApproval"`
	State            string        `json:"state"`
	PasswordRequired bool          `json:"passwordRequired"`
	Life             int           `json:"life"`
	Label            string        `json:"label"`
	IsVDR            bool          `json:"isVDR"`
	IsArchived       bool          `json:"isArchived"`
	PackageSender    string        `json:"packageSender"`
	PackageTimestamp string        `json:"packageTimestamp"`
	RootDirectoryID  string        `json:"rootDirectoryId"`
	Response         string        `json:"response"`
}

type File struct {
	FileID          string `json:"fileId"`
	FileName        string `json:"fileName"`
	FileSize        string `json:"fileSize"`
	Parts           int    `json:"parts"`
	FileUploaded    string `json:"fileUploaded"`
	FileUploadedStr string `json:"fileUploadedStr"`
	FileVersion     string `json:"fileVersion"`
	CreatedByEmail  string `json:"createdByEmail"`
}

type PackageMetadata struct {
	Thread      string
	PackageCode string
	KeyCode     string
}

func NewAPI(Host string, APIKey string, APISecret string) *API {
	c := &API{
		host:      Host,
		apiKey:    APIKey,
		apiSecret: APISecret,
	}
	return c
}

func computeHmac256(secret string, data string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func createSignature(APIKey string, APISecret string, URL string, dateString string, data string) string {
	content := APIKey + URL + dateString + data
	hash := computeHmac256(APISecret, content)
	return hash
}

func addCredentials(APIKey string, APISecret string, req *http.Request, URL string, data []byte, date time.Time) {
	dateString := getDateString(date)
	signature := createSignature(APIKey, APISecret, URL, dateString, string(data))
	req.Header.Add(APIKeyHeader, APIKey)
	req.Header.Add(TimestampHeader, dateString)
	req.Header.Add(SignatureHeader, signature)
}

func getDateString(date time.Time) string {
	d := date.Format(time.RFC3339)
	return fmt.Sprintf("%s%s", d[:len(d)-1], "+0000")
}

func (a *API) makeRequest(endpointURL string, method string, data []byte, stream bool) (*http.Request, error) {
	endpointURL = URLAPIPrefix + endpointURL
	fullURL := a.host + endpointURL

	req, err := http.NewRequest(method, fullURL, bytes.NewReader([]byte(data)))
	if err != nil {
		return nil, err
	}

	addCredentials(a.apiKey, a.apiSecret, req, endpointURL, data, time.Now().UTC())

	req.Header.Add("Content-Type", ContentType)

	return req, nil
}

func (a *API) sendRequest(endpointURL string, method string, data []byte, stream bool) (io.Reader, error) {
	req, err := a.makeRequest(endpointURL, method, data, stream)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if r.StatusCode != 200 {
		return nil, fmt.Errorf("Got HTTP status code: %d", r.StatusCode)
	}

	return r.Body, nil
}

func createChecksum(keyCode string, packageCode string) string {
	key := pbkdf2.WithHMAC(sha256.New, []byte(keyCode), []byte(packageCode), 1024, 64)
	key = key[:32]
	return fmt.Sprintf("%x", key)
}

func (a *API) DownloadFile(pm PackageMetadata, p Package, f File) error {
	method := "POST"
	path := "/package/" + p.PackageID + "/file/" + f.FileID + "/download/"

	password := []byte(p.ServerSecret + pm.KeyCode)
	cs := createChecksum(pm.KeyCode, p.PackageCode)

	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if failed {
			return nil, errors.New("decryption failed")
		}
		failed = true
		return password, nil
	}

	outputFile, err := os.OpenFile("/tmp/"+f.FileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	for i := 1; i <= f.Parts; i++ {
		fmt.Printf("DownloadFilePart %d\n", i)

		postParams := make(map[string]string, 3)
		postParams["checksum"] = cs
		postParams["part"] = strconv.Itoa(i)
		postParams["api"] = "JAVA_API"

		pp, err := json.Marshal(postParams)
		if err != nil {
			return err
		}

		r, err := a.sendRequest(path, method, pp, false)
		if err != nil {
			return err
		}

		failed = false

		md, err := openpgp.ReadMessage(r, nil, prompt, nil)
		if err != nil {
			return err
		}

		_, err = io.Copy(outputFile, md.UnverifiedBody)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *API) UserInformation() (UserInformation, error) {
	var ui UserInformation
	method := "GET"
	path := "/user/"

	r, err := a.sendRequest(path, method, []byte{}, false)
	if err != nil {
		return ui, err
	}

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return ui, err
	}

	err = json.Unmarshal(b, &ui)
	if err != nil {
		return ui, err
	}

	return ui, nil
}

func (a *API) GetPackageMetadataFromURL(packageURL string) (PackageMetadata, error) {
	var pm PackageMetadata

	v, err := url.Parse(packageURL)
	if err != nil {
		return pm, err
	}

	q := v.Query()

	pm.PackageCode = q.Get("packageCode")
	pm.Thread = q.Get("thread")
	pm.KeyCode = ""

	// packageURL = "https://files.test.com/receive/?thread=ABCD-EFGH&packageCode=11dd22ee33ff#keyCode=55aa66bb77cc
	p := strings.Split(packageURL, "#")
	// p = "https://files.test.com/receive/?thread=ABCD-EFGH&packageCode=11dd22ee33ff"
	//     "keyCode=55aa66bb77cc"
	if len(p) == 2 {
		p := strings.Split(p[1], "=")
		// p = "keyCode"
		//     "55aa66bb77cc"
		if len(p) == 2 {
			if p[0] == "keyCode" {
				pm.KeyCode = p[1]
			}
		}
	}

	if pm.PackageCode == "" || pm.Thread == "" || pm.KeyCode == "" {
		return PackageMetadata{"", "", ""}, fmt.Errorf("Could not find packageCode, thread or keyCode in URL")
	}

	return pm, nil
}

func (a *API) GetPackage(packageCode string) (Package, error) {
	var p Package
	packageURL := fmt.Sprintf("/package/%s", packageCode)

	r, err := a.sendRequest(packageURL, "GET", []byte{}, false)
	if err != nil {
		return p, err
	}

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return p, err
	}

	err = json.Unmarshal(b, &p)
	if err != nil {
		return p, err
	}
	return p, nil
}

func (a *API) GetPackageFromURL(packageURL string) (Package, error) {
	var p Package

	pm, err := a.GetPackageMetadataFromURL(packageURL)
	if err != nil {
		return p, err
	}

	p, err = a.GetPackage(pm.PackageCode)
	if err != nil {
		return p, err
	}

	return p, nil
}
