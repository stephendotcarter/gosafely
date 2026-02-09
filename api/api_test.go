package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp"
)

// encryptTestData encrypts data with password using PGP symmetric encryption.
func encryptTestData(data []byte, password string) ([]byte, error) {
	var buf bytes.Buffer
	w, err := openpgp.SymmetricallyEncrypt(&buf, []byte(password), nil, nil)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// mockServerConfig configures the mock download server.
type mockServerConfig struct {
	parts      [][]byte      // encrypted data for each part
	delay      time.Duration // delay per request
	failOnPart int           // return error on this part (1-indexed, 0 = no failure)
}

// newMockDownloadServer creates a test server that handles download requests.
// It returns the server and the password used for encryption.
func newMockDownloadServer(cfg mockServerConfig) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.delay > 0 {
			time.Sleep(cfg.delay)
		}

		// Parse request body to get part number
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var params struct {
			Part string `json:"part"`
		}
		if err := json.Unmarshal(body, &params); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		var partNum int
		fmt.Sscanf(params.Part, "%d", &partNum)

		if partNum < 1 || partNum > len(cfg.parts) {
			http.Error(w, "invalid part", http.StatusBadRequest)
			return
		}

		// Simulate failure on specific part
		if cfg.failOnPart == partNum {
			http.Error(w, "simulated error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(cfg.parts[partNum-1])
	}))
}

// generateTestParts creates encrypted test data for each part.
func generateTestParts(numParts, partSize int, password string) ([][]byte, []byte, error) {
	var allData []byte
	parts := make([][]byte, numParts)

	for i := 0; i < numParts; i++ {
		// Generate deterministic data for each part
		data := bytes.Repeat([]byte{byte(i)}, partSize)
		allData = append(allData, data...)

		encrypted, err := encryptTestData(data, password)
		if err != nil {
			return nil, nil, err
		}
		parts[i] = encrypted
	}

	return parts, allData, nil
}

func TestComputeHmac256(t *testing.T) {
	tables := []struct {
		secret   string
		data     string
		expected string
	}{
		{"iouWFiuv8oz8E8cbJE3tTx", "953Ud1CoFvAh0UCWuvT7Ig/api/v2.0/package/31B0Mrkba0ag30tjzwXi2SkR6Cr1k3CfpkfHinRBqjg/2018-10-29T08:34:08+0000", "173F1DF7E79CAF18A2CF3081A0933F12FEE2EC19DA4F08F284763A2EA50AF9E7"},
		{"iouWFiuv8oz8E8cbJE3tTx", "953Ud1CoFvAh0UCWuvT7Ig/api/v2.0/package/S1MB-RP9V/file/6e07a288-6382-4ca4-8831-cda972e32797/download/2018-10-29T08:36:22+0000{\"part\":1,\"checksum\":\"298dc33a5ce68159ff848b9b1c8674561a70c3594cdb05d3baa807e4f7a6f10b\",\"api\":\"JAVA_API\"}", "CB28AF3EB125E0FAF458846F7F640FD329325440B6615D39B36AEBF85CE77685"},
	}

	for _, table := range tables {
		result := computeHmac256(table.secret, table.data)
		if result != table.expected {
			t.Errorf("ComputeHmac256 of (%s + %s) was incorrect, got: %s, want: %s.", table.secret, table.data, result, table.expected)
		}
	}
}

func TestCreateChecksum(t *testing.T) {
	tables := []struct {
		keyCode     string
		packageCode string
		expected    string
	}{
		{"aXaQiWhw9p29CAoDoLRxpWbzotX2Qe0D-0agiN_RYXU", "30B0MrkbR8ag31tjzwXi2SkR6Cr1k3CfpkfHinRBqjg", "108fef6ace973f462c1d73be2e8ec6ccd2f1c1a64131e5375adce7840aaa33fd"},
		{"vdDpzVFc7b9T1ESiGnEQymySEsc2CDT-bly2oAMzP0s", "aa2AAONA0fiVWV4Hwo0Rn3084cjfgLpDP11jphMOoS0", "54a6f0b84a7ec0ee2ca453b8c43ce8da1d29e3575bb954e214f209df0ca495f5"},
	}

	for _, table := range tables {
		result := createChecksum(table.keyCode, table.packageCode)
		if result != table.expected {
			t.Errorf("CreateChecksum of (%s + %s) was incorrect, got: %s, want: %s.", table.keyCode, table.packageCode, result, table.expected)
		}
	}
}

func TestCreateSignature(t *testing.T) {
	tables := []struct {
		APIKey     string
		APISecret  string
		URL        string
		dateString string
		data       string
		expected   string
	}{
		{"853Ud1CoFvAh0UCWuvT6Ig", "abcWFhuv8oz8E8cbJE3tTw", "/api/v2.0/package/30B0MrkbR0ag30tjzwXi2SkR6Cr1k3CfpkfHinRBqjg/", "2018-10-29T08:36:21+0000", "", "74485306DABB6A0594B2E852B53C009ECE42201D1897783D028FE9BD8F214150"},
		{"853Ud1CoFvAh0UCWuvT6Ig", "abcWFhuv8oz8E8cbJE3tTw", "/api/v2.0/package/ABCD-EFGH/file/6e07a288-6382-4ca4-9931-adc972e32797/download/", "2018-10-29T09:20:12+0000", "{\"part\":1,\"checksum\":\"298dc53a5ce68159ff848b9b1c8674561a70c3594cdb05d3baa807e4f7a6f10b\",\"api\":\"JAVA_API\"}", "232C6B666356949650784F55EF5E1106399514F91F3F39D49D6EEB9C409EBAC2"},
		{"853Ud1CoFvAh0UCWuvT6Ig", "abcWFhuv8oz8E8cbJE3tTw", "/api/v2.0/package/EFGH-ABCD/file/6e07a288-6382-4ca4-9931-adc972e32797/download/", "2018-10-29T09:56:04+0000", "{\"part\":1,\"checksum\":\"298dc53a5ce68159ff848b9b1c8674561a70c3594cdb05d3baa807e4f7a6f10b\",\"api\":\"JAVA_API\"}", "30F54852565C9701F77E0613E09CFD519DCABEA7FED9BE03FF212CC5E1BE875C"},
	}

	for _, table := range tables {
		result := createSignature(table.APIKey, table.APISecret, table.URL, table.dateString, table.data)
		if result != table.expected {
			t.Errorf("createSignature was incorrect, got: %s, want: %s.", result, table.expected)
		}
	}
}

func TestAddCredentials(t *testing.T) {
	tables := []struct {
		APIKey            string
		APISecret         string
		URL               string
		data              []byte
		date              time.Time
		expectedDate      string
		expectedSignature string
	}{
		{
			"1234",
			"5678",
			"/path/to/endpoint",
			[]byte("{\"hello\":\"world\"}"),
			time.Date(2018, 10, 29, 14, 30, 00, 000000000, time.UTC),
			"2018-10-29T14:30:00+0000",
			"34DA63B5BF9B85606B6442CFB5680D4131C71C0E09CE346098DB7658C334DBF9",
		}, {
			"aabbcc112233",
			"5678",
			"/path/to/endpoint",
			[]byte("{\"send\":\"safely\"}"),
			time.Date(2018, 1, 1, 1, 1, 1, 000000000, time.UTC),
			"2018-01-01T01:01:01+0000",
			"C5F48D19B5E39004757C03DE41D72B7C8818F7AAD7DCD3D513F768B1F470B325",
		},
	}

	for _, table := range tables {
		req, _ := http.NewRequest("GET", table.URL, bytes.NewReader([]byte(table.data)))

		addCredentials(table.APIKey, table.APISecret, req, table.URL, table.data, table.date)

		actualAPIKey := req.Header.Get(APIKeyHeader)
		actualDate := req.Header.Get(TimestampHeader)
		actualSignature := req.Header.Get(SignatureHeader)

		if actualAPIKey != table.APIKey {
			t.Errorf("Expected \"%s\" to equal \"%s\", actual \"%s\"", APIKeyHeader, table.APIKey, actualAPIKey)
		}
		if actualDate != table.expectedDate {
			t.Errorf("Expected \"%s\" to equal \"%s\", actual \"%s\"", TimestampHeader, table.expectedDate, actualDate)
		}
		if actualSignature != table.expectedSignature {
			t.Errorf("Expected \"%s\" to equal \"%s\", actual \"%s\"", SignatureHeader, table.expectedSignature, actualSignature)
		}
	}
}

func TestGetPackageMetadataFromURL(t *testing.T) {
	tables := []struct {
		URL      string
		expected PackageMetadata
		err      string
	}{
		{"https://files.test.com/receive/?thread=ABCD-EFGH&packageCode=11aa22bb33cc#keyCode=dd44ee55ff66", PackageMetadata{"ABCD-EFGH", "11aa22bb33cc", "dd44ee55ff66"}, ""},
		{"https://files.test.com/receive/?thread=ABCD-EFGH&packageode=11aa22bb33cc#keyCode=dd44ee55ff66fakeparam=fakevalue", PackageMetadata{"", "", ""}, "Could not find packageCode, thread or keyCode in URL"},
		{"https://files.test.com/receive/?thread=ABCD-EFGH&packageCode=11aa22bb33cc#keyCode=dd44ee55ff66#fakeparam=fakevalue", PackageMetadata{"", "", ""}, "Could not find packageCode, thread or keyCode in URL"},
	}

	a := NewAPI("host", "key", "secret")

	for _, table := range tables {
		value, err := a.GetPackageMetadataFromURL(table.URL)
		errString := ""
		if err != nil {
			errString = err.Error()
		}
		if value != table.expected || errString != table.err {
			t.Errorf("GetPackageMetadataFromURL was incorrect, got: (\"%s\", \"%s\"), want: (\"%s\", \"%s\").", value, err, table.expected, table.err)
		}
	}
}

func TestDownloadFile(t *testing.T) {
	// Password = ServerSecret + KeyCode
	const testServerSecret = "test-server-secret"
	const testKeyCode = "test-key-code"
	const testPassword = testServerSecret + testKeyCode

	tests := []struct {
		name           string
		parts          int
		partSize       int
		concurrency    int
		failOnPart     int
		wantErr        bool
		checkTempFiles bool
	}{
		{
			name:        "sequential single part",
			parts:       1,
			partSize:    1024,
			concurrency: 0,
		},
		{
			name:        "sequential multi part",
			parts:       4,
			partSize:    1024,
			concurrency: 0,
		},
		{
			name:        "concurrent multi part",
			parts:       8,
			partSize:    1024,
			concurrency: 4,
		},
		{
			name:           "temp files cleaned on success",
			parts:          4,
			partSize:       1024,
			concurrency:    4,
			checkTempFiles: true,
		},
		{
			name:           "temp files cleaned on error",
			parts:          4,
			partSize:       1024,
			concurrency:    4,
			failOnPart:     2,
			wantErr:        true,
			checkTempFiles: true,
		},
		{
			name:        "error propagates correctly",
			parts:       4,
			partSize:    1024,
			concurrency: 4,
			failOnPart:  3,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test data
			parts, expectedData, err := generateTestParts(tt.parts, tt.partSize, testPassword)
			if err != nil {
				t.Fatalf("failed to generate test parts: %v", err)
			}

			// Start mock server
			server := newMockDownloadServer(mockServerConfig{
				parts:      parts,
				failOnPart: tt.failOnPart,
			})
			defer server.Close()

			// Create API pointing to mock server
			api := &API{
				host:        server.URL,
				concurrency: tt.concurrency,
			}

			// Create temp directory for output
			tmpDir, err := ioutil.TempDir("", "download-test")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			outputFile := filepath.Join(tmpDir, "output.bin")

			// Create test metadata
			pm := PackageMetadata{
				KeyCode:     testKeyCode,
				PackageCode: "test-package",
			}
			pkg := Package{
				PackageID:    "test-pkg-id",
				ServerSecret: testServerSecret,
			}

			file := File{
				FileID:   "test-file-id",
				Parts:    tt.parts,
				FileSize: fmt.Sprintf("%d", tt.parts*tt.partSize),
			}

			// Call DownloadFile
			err = api.DownloadFile(pm, pkg, file, outputFile, ProgressNone)

			// Check error expectation
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				// Verify file content
				content, err := ioutil.ReadFile(outputFile)
				if err != nil {
					t.Fatalf("failed to read output file: %v", err)
				}
				if !bytes.Equal(content, expectedData) {
					t.Errorf("file content mismatch: got %d bytes, want %d bytes", len(content), len(expectedData))
				}
			}

			// Check temp files are cleaned up
			if tt.checkTempFiles {
				files, _ := filepath.Glob(filepath.Join(tmpDir, "*.tmp"))
				if len(files) > 0 {
					t.Errorf("temp files not cleaned up: %v", files)
				}
			}
		})
	}
}

func TestDownloadFileProgress(t *testing.T) {
	// Password = ServerSecret + KeyCode
	const testServerSecret = "test-server-secret"
	const testKeyCode = "test-key-code"
	const testPassword = testServerSecret + testKeyCode
	const numParts = 4
	const partSize = 1024

	// Generate test data
	parts, _, err := generateTestParts(numParts, partSize, testPassword)
	if err != nil {
		t.Fatalf("failed to generate test parts: %v", err)
	}

	// Start mock server
	server := newMockDownloadServer(mockServerConfig{
		parts: parts,
	})
	defer server.Close()

	// Create API with concurrency
	api := &API{
		host:        server.URL,
		concurrency: 4,
	}

	// Create temp directory for output
	tmpDir, err := ioutil.TempDir("", "download-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	outputFile := filepath.Join(tmpDir, "output.bin")

	// Track progress calls
	var mu sync.Mutex
	var progressCalls []uint64

	progressFn := func(current, total uint64) {
		mu.Lock()
		progressCalls = append(progressCalls, current)
		mu.Unlock()
	}

	// Create test metadata
	pm := PackageMetadata{
		KeyCode: testKeyCode,
	}
	pkg := Package{
		PackageID:    "test-pkg-id",
		ServerSecret: testServerSecret,
	}
	file := File{
		FileID:   "test-file-id",
		Parts:    numParts,
		FileSize: fmt.Sprintf("%d", numParts*partSize),
	}

	// Call DownloadFile
	err = api.DownloadFile(pm, pkg, file, outputFile, progressFn)
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}

	// Verify progress was reported
	if len(progressCalls) == 0 {
		t.Error("progress callback was never called")
	}

	// Verify final progress equals total size
	expectedTotal := uint64(numParts * partSize)
	finalProgress := progressCalls[len(progressCalls)-1]
	if finalProgress != expectedTotal {
		t.Errorf("final progress %d != expected total %d", finalProgress, expectedTotal)
	}

	// Verify progress is monotonically increasing (for sequential) or at least reaches total (for concurrent)
	// For concurrent, values may not be strictly increasing due to race, but should all be <= total
	for _, p := range progressCalls {
		if p > expectedTotal {
			t.Errorf("progress %d exceeds total %d", p, expectedTotal)
		}
	}
}
