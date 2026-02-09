package api

import (
	"bytes"
	"context"
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
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dchest/pbkdf2"
	humanize "github.com/dustin/go-humanize"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/sync/errgroup"
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
	host        string
	apiKey      string
	apiSecret   string
	concurrency int // number of concurrent part downloads; 0 or 1 = sequential
}

// SetConcurrency sets the number of concurrent part downloads.
// When concurrency is 0 or 1, downloads are sequential.
// When concurrency > 1, parts are downloaded in parallel.
func (a *API) SetConcurrency(n int) {
	a.concurrency = n
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

type PackageMetadata struct {
	Thread      string
	PackageCode string
	KeyCode     string
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

func (f *File) FileSizeInt() uint64 {
	i, _ := strconv.Atoi(f.FileSize)
	return uint64(i)
}

func (f *File) FileSizeHumanize() string {
	return humanize.Bytes(f.FileSizeInt())
}

type writeCounter struct {
	Current  uint64
	Total    uint64
	Progress func(uint64, uint64)
}

func (wc *writeCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Current += uint64(n)
	wc.Progress(wc.Current, wc.Total)
	return n, nil
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

func createSignature(
	APIKey string, APISecret string, URL string, dateString string, data string,
) string {
	content := APIKey + URL + dateString + data
	hash := computeHmac256(APISecret, content)
	return hash
}

func addCredentials(
	APIKey string, APISecret string, req *http.Request, URL string, data []byte, date time.Time,
) {
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

func (a *API) makeRequest(
	endpointURL string, method string, data []byte, stream bool,
) (*http.Request, error) {
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

func (a *API) sendRequest(
	endpointURL string, method string, data []byte, stream bool,
) (io.Reader, error) {
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

func (a *API) DownloadFile(
	pm PackageMetadata, p Package, f File, fp string, progress func(uint64, uint64),
) error {
	if _, err := os.Stat(fp); !os.IsNotExist(err) {
		return fmt.Errorf("File exists")
	}

	if a.concurrency <= 1 {
		return a.downloadFileSequential(pm, p, f, fp, progress)
	}
	return a.downloadFileConcurrent(pm, p, f, fp, progress)
}

// downloadFileSequential downloads file parts one at a time.
func (a *API) downloadFileSequential(
	pm PackageMetadata, p Package, f File, fp string, progress func(uint64, uint64),
) error {
	method := "POST"
	path := "/package/" + p.PackageID + "/file/" + f.FileID + "/download/"

	fh, err := os.OpenFile(fp, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer fh.Close()

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

	counter := &writeCounter{
		0,
		f.FileSizeInt(),
		progress,
	}

	for i := 1; i <= f.Parts; i++ {
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

		_, err = io.Copy(fh, io.TeeReader(md.UnverifiedBody, counter))
		if err != nil {
			return err
		}
	}
	return nil
}

// downloadFileConcurrent downloads file parts concurrently using a worker pool.
func (a *API) downloadFileConcurrent(
	pm PackageMetadata, p Package, f File, fp string, progress func(uint64, uint64),
) error {
	method := "POST"
	path := "/package/" + p.PackageID + "/file/" + f.FileID + "/download/"

	password := []byte(p.ServerSecret + pm.KeyCode)
	cs := createChecksum(pm.KeyCode, p.PackageCode)

	// Generate temp file paths for each part
	dir := filepath.Dir(fp)
	base := filepath.Base(fp)
	tempFiles := make([]string, f.Parts)
	for i := 0; i < f.Parts; i++ {
		tempFiles[i] = filepath.Join(dir, fmt.Sprintf("%s.part%d.tmp", base, i+1))
	}

	// Cleanup function to remove temp files
	cleanup := func() {
		for _, tf := range tempFiles {
			os.Remove(tf)
		}
	}

	// Track progress atomically
	var downloaded uint64
	total := f.FileSizeInt()

	// Use errgroup for concurrent downloads with cancellation
	g, ctx := errgroup.WithContext(context.Background())

	// Semaphore to limit concurrency
	sem := make(chan struct{}, a.concurrency)

	for i := 1; i <= f.Parts; i++ {
		partNum := i
		tempFile := tempFiles[i-1]

		g.Go(func() error {
			// Acquire semaphore
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			defer func() { <-sem }()

			// Check if context was cancelled
			if ctx.Err() != nil {
				return ctx.Err()
			}

			// Download and decrypt part
			err := a.downloadPart(path, method, cs, partNum, password, tempFile, func(n uint64) {
				current := atomic.AddUint64(&downloaded, n)
				progress(current, total)
			})
			if err != nil {
				return fmt.Errorf("part %d: %w", partNum, err)
			}
			return nil
		})
	}

	// Wait for all downloads to complete
	if err := g.Wait(); err != nil {
		cleanup()
		return err
	}

	// Assemble parts into final file
	fh, err := os.OpenFile(fp, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		cleanup()
		return err
	}
	defer fh.Close()

	for _, tempFile := range tempFiles {
		tf, err := os.Open(tempFile)
		if err != nil {
			cleanup()
			return err
		}
		_, err = io.Copy(fh, tf)
		tf.Close()
		if err != nil {
			cleanup()
			return err
		}
	}

	// Cleanup temp files after successful assembly
	cleanup()
	return nil
}

// downloadPart downloads and decrypts a single part to a temp file.
func (a *API) downloadPart(
	path, method, checksum string,
	partNum int,
	password []byte,
	tempFile string,
	onProgress func(uint64),
) error {
	postParams := map[string]string{
		"checksum": checksum,
		"part":     strconv.Itoa(partNum),
		"api":      "JAVA_API",
	}

	pp, err := json.Marshal(postParams)
	if err != nil {
		return err
	}

	r, err := a.sendRequest(path, method, pp, false)
	if err != nil {
		return err
	}

	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if failed {
			return nil, errors.New("decryption failed")
		}
		failed = true
		return password, nil
	}

	md, err := openpgp.ReadMessage(r, nil, prompt, nil)
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(tempFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer fh.Close()

	// Wrap with progress tracking
	pr := &progressReader{r: md.UnverifiedBody, onProgress: onProgress}
	_, err = io.Copy(fh, pr)
	return err
}

// progressReader wraps a reader and calls onProgress with bytes read.
type progressReader struct {
	r          io.Reader
	onProgress func(uint64)
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	if n > 0 {
		pr.onProgress(uint64(n))
	}
	return n, err
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

func ProgressPrintBytes(current uint64, total uint64) {
	fmt.Printf("\r%s", strings.Repeat(" ", 35))
	fmt.Printf("\r%s/%s", humanize.Bytes(current), humanize.Bytes(total))
}

func ProgressNone(current uint64, total uint64) {}
