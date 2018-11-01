package main

import (
	"fmt"
	"os"

	gosafely "github.com/stephendotcarter/gosafely/api"
)

func main() {
	apiURL := os.Getenv("SS_API_URL")
	apiKeyID := os.Getenv("SS_API_KEY_ID")
	apiKeySecret := os.Getenv("SS_API_KEY_SECRET")

	sampleURL := os.Getenv("SAMPLE_URL")

	api := gosafely.NewAPI(apiURL, apiKeyID, apiKeySecret)

	u, err := api.UserInformation()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Logged in as %s (%s)\n", u.FirstName, u.Email)

	pm, err := api.GetPackageMetadataFromURL(sampleURL)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	p, err := api.GetPackage(pm.PackageCode)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Package Sender: %s\n", p.PackageSender)
	fmt.Printf("Package Files:\n")
	for i, f := range p.Files {
		fmt.Printf("%d: %s (%s)\n", i, f.FileName, f.FileSize)
		api.DownloadFile(pm, p, f)
	}
}
