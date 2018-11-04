package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	gosafely "github.com/stephendotcarter/gosafely/api"
)

var (
	version      string
	apiURL       = os.Getenv("SS_API_URL")
	apiKeyID     = os.Getenv("SS_API_KEY_ID")
	apiKeySecret = os.Getenv("SS_API_KEY_SECRET")
	api          *gosafely.API
	ssURL        string
)

var rootCmd = &cobra.Command{
	Use:   "gosafely",
	Short: "gosafely is a CLI for SendSafely",
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of gosafely",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", version)
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List the files in a package",
	Run: func(cmd *cobra.Command, args []string) {
		p, err := getPackage(ssURL)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		printPackage(p)
	},
}

func getPackage(packageURL string) (gosafely.Package, error) {
	var p gosafely.Package
	pm, err := api.GetPackageMetadataFromURL(packageURL)
	if err != nil {
		return p, err
	}
	p, err = api.GetPackage(pm.PackageCode)
	if err != nil {
		return p, err
	}
	return p, nil
}

func printPackage(p gosafely.Package) {
	fmt.Println("")
	table := tablewriter.NewWriter(os.Stdout)
	table.Append([]string{"Package", p.PackageCode})
	table.Append([]string{"Sent by", p.PackageSender})
	table.Append([]string{"Sent on", p.PackageTimestamp})
	table.SetBorder(false)
	table.Render()
	fmt.Println("")

	printFiles(p.Files)
}

func printFiles(files []gosafely.File) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"#", "Uploaded", "Size", "File Name"})
	for i, v := range files {
		table.Append([]string{
			strconv.Itoa(i),
			v.FileUploadedStr,
			v.FileSizeHumanize(),
			v.FileName,
		})
	}
	table.Render()
}

func init() {
	if apiURL == "" || apiKeyID == "" || apiKeySecret == "" {
		fmt.Println("SS_API_URL, SS_API_KEY_ID and SS_API_KEY_SECRET environment variables required")
		os.Exit(1)
	}

	api = gosafely.NewAPI(apiURL, apiKeyID, apiKeySecret)

	rootCmd.AddCommand(versionCmd)

	listCmd.Flags().StringVarP(&ssURL, "url", "u", "", "SendSafely URL to query")
	listCmd.MarkFlagRequired("url")
	rootCmd.AddCommand(listCmd)
}

func execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	execute()
}
