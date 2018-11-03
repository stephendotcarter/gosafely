package api

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

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
