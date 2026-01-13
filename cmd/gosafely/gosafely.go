package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
	gosafely "github.com/stephendotcarter/gosafely/api"
)

var (
	version      string
	apiURL       = os.Getenv("SS_API_URL")
	apiKeyID     = os.Getenv("SS_API_KEY_ID")
	apiKeySecret = os.Getenv("SS_API_KEY_SECRET")
	ssAPI        *gosafely.API
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
		checkEnvVars()
		p, _, err := getPackage(ssURL)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		printPackage(p)
	},
}

var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download the files in a package",
	Run: func(cmd *cobra.Command, args []string) {
		checkEnvVars()

		p, pm, err := getPackage(ssURL)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		printPackage(p)

		selected, err := getDownloadIndices(len(p.Files))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("")
		for _, s := range selected {
			fp := "./" + p.Files[s].FileName
			fmt.Printf("Downloading %s\n", p.Files[s].FileName)
			err = ssAPI.DownloadFile(pm, p, p.Files[s], fp, gosafely.ProgressPrintBytes)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println()
		}
	},
}

func getDownloadIndices(fc int) ([]int64, error) {
	validate := func(input string) error {
		_, err := getIndices(input, fc)
		if err != nil {
			return err
		}
		return nil
	}

	// Default all files selected
	selectedDefault := []string{}
	for i := 0; i < fc; i++ {
		selectedDefault = append(selectedDefault, strconv.Itoa(i))
	}

	prompt := promptui.Prompt{
		Label:    "Files",
		Validate: validate,
		Templates: &promptui.PromptTemplates{
			Success: "{{ . | faint }} ",
		},
		Default: strings.Join(selectedDefault, ","),
	}
	result, err := prompt.Run()

	selected, err := getIndices(result, fc)
	if err != nil {
		return selected, err
	}
	return selected, nil
}

func getIndices(input string, fc int) ([]int64, error) {
	input = strings.Replace(input, " ", "", -1)
	selected := []int64{}
	for _, i := range strings.Split(input, ",") {
		ip, err := strconv.ParseInt(i, 10, 64)
		if err != nil {
			return nil, errors.New("Index must be a number")
		}
		if ip >= int64(fc) {
			return nil, fmt.Errorf("Index must be between %d and %d", 0, fc-1)
		}
		selected = append(selected, ip)
	}

	return selected, nil
}

func getPackage(packageURL string) (gosafely.Package, gosafely.PackageMetadata, error) {
	var p gosafely.Package
	var pm gosafely.PackageMetadata
	pm, err := ssAPI.GetPackageMetadataFromURL(packageURL)
	if err != nil {
		return p, pm, err
	}
	p, err = ssAPI.GetPackage(pm.PackageCode)
	if err != nil {
		return p, pm, err
	}
	return p, pm, nil
}

func printPackage(p gosafely.Package) {
	fmt.Println("")
	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRendition(tw.Rendition{
			Borders: tw.Border{Left: tw.Off, Right: tw.Off, Top: tw.Off, Bottom: tw.Off},
		}),
	)
	table.Append([]string{"Package", p.PackageCode})
	table.Append([]string{"Sent by", p.PackageSender})
	table.Append([]string{"Sent on", p.PackageTimestamp})
	table.Render()
	fmt.Println("")

	printFiles(p.Files)
}

func printFiles(files []gosafely.File) {
	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithHeader([]string{"#", "Uploaded", "Size", "File Name"}),
	)
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

func checkEnvVars() {
	if apiURL == "" || apiKeyID == "" || apiKeySecret == "" {
		fmt.Println("SS_API_URL, SS_API_KEY_ID and SS_API_KEY_SECRET environment variables required")
		os.Exit(1)
	}
}

func init() {

	ssAPI = gosafely.NewAPI(apiURL, apiKeyID, apiKeySecret)

	rootCmd.AddCommand(versionCmd)

	listCmd.Flags().StringVarP(&ssURL, "url", "u", "", "SendSafely URL to query")
	listCmd.MarkFlagRequired("url")
	rootCmd.AddCommand(listCmd)

	downloadCmd.Flags().StringVarP(&ssURL, "url", "u", "", "SendSafely URL to query")
	downloadCmd.MarkFlagRequired("url")
	rootCmd.AddCommand(downloadCmd)
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
