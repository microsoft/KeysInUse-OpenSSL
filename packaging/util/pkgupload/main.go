package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"

	"github.com/Azure/go-autorest/autorest/adal"
)

type UploadedFile struct {
	Id    string `json:"id"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
	Size  int    `json:"size"`
}

// Body of the response returned from a successful call
// to the /files/multi endpoint
type FileUploadRes struct {
	Id              string         `json:"id"`
	UploadDirectory string         `json:"uploadDirectory"`
	UploadId        string         `json:"uploadId"`
	UploadedFiles   []UploadedFile `json:"uploadedFiles"`
}

type Package struct {
	FileName     string `json:"fileName,omitempty"`
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	RepositoryId string `json:"repositoryId,omitempty"`
}

// Body of the request send to the /packages endpoint
type PackagePublishReq struct {
	RepositoryId string    `json:"repositoryId"`
	FileId       string    `json:"fileId,omitempty"`
	SourceUrl    string    `json:"sourceUrl,omitempty"`
	Packages     []Package `json:"packages"`
}

const (
	aadEndPoint = "https://login.microsoftonline.com/"

	repoBaseUrl         = "https://azure-apt-cat.cloudapp.net/v3"
	repoPackageEndpoint = repoBaseUrl + "/packages"
	repoFilesEndpoint   = repoBaseUrl + "/files/multi"
)

func main() {
	var tenantId string
	var clientId string
	var resourceId string
	var certPath string
	var repoId string
	var pkgDir string
	var isDebian bool
	flag.StringVar(&tenantId, "tid", "", "Tenant ID of app registration to authenticate")
	flag.StringVar(&clientId, "cid", "", "Client ID of app registration to authenticate")
	flag.StringVar(&resourceId, "rid", "", "Resource ID of app registration to authenticate")
	flag.StringVar(&certPath, "p", "", "Path to certificate file to authenticate")
	flag.StringVar(&repoId, "r", "", "The repo ID to upload the package to")
	flag.BoolVar(&isDebian, "deb", false, "Set if uploading debian packages")

	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] package_directory\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	pkgDir = flag.Arg(0)

	if tenantId == "" ||
		clientId == "" ||
		resourceId == "" ||
		certPath == "" ||
		repoId == "" {
		log.Fatalf("Required arguments not passed")

	}

	fmt.Printf("Uploading packages in %s to repo %s\n", pkgDir, repoId)

	privateKey, certificate, err := DecodePemFile(certPath)
	if err != nil {
		log.Fatalf(err.Error())
	}

	aadToken, err := AuthorizeAAD(tenantId, clientId, resourceId, privateKey, certificate)
	if err != nil {
		log.Fatalf(err.Error())
	}

	err = UploadPackages(aadToken, pkgDir, repoId, isDebian)
	if err != nil {
		log.Fatalf(err.Error())
	}
}

func GenerateGUID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// DecodePemFile reads the pem file at pemFilePath and returns the
// private key and certificate contained. This function assumes
// the private key is the first block of the pem file, and the
// public certificate is the second block
func DecodePemFile(pemFilePath string) (*rsa.PrivateKey, *x509.Certificate, error) {
	var privateKey *rsa.PrivateKey
	var certificate *x509.Certificate

	pemBytes, err := ioutil.ReadFile(pemFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read pem file: %v", err)
	}

	keyPem, pemBytes := pem.Decode(pemBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get private key from pem: %v", err)
	}

	pKeyRaw, err := x509.ParsePKCS8PrivateKey(keyPem.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	var ok bool
	if privateKey, ok = pKeyRaw.(*rsa.PrivateKey); !ok {
		return nil, nil, fmt.Errorf("found key of unexpected type (not rsa) in pem")
	}

	certPem, _ := pem.Decode(pemBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get cert from pem: %v", err)
	}
	certificate, err = x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse x509 certificate from pem bytes: %v", err)
	}

	return privateKey, certificate, nil
}

// AuthorizeAAD acquires a service principal token for the keysinuse
// application registration in the Microsoft AAD. This token is used
// to authenticate with the package repo
func AuthorizeAAD(tenantId string,
	clientId string,
	resourceId string,
	privateKey *rsa.PrivateKey,
	certificate *x509.Certificate) (string, error) {

	oathConfig, err := adal.NewOAuthConfig(aadEndPoint, tenantId)
	if err != nil {
		return "", fmt.Errorf("failed to set up oath config: %v", err)
	}

	spt, err := adal.NewServicePrincipalTokenFromCertificate(
		*oathConfig,
		clientId,
		certificate,
		privateKey,
		resourceId)

	if err != nil {
		return "", fmt.Errorf("failed to get AAD token: %v", err)
	}

	err = spt.Refresh()
	if err != nil {
		return "", fmt.Errorf("failed to refresh AAD token: %v", err)
	}

	return fmt.Sprintf("%s %s", spt.Token().Type, spt.OAuthToken()), nil
}

// UploadPackages uploads all package files in 'dir' and publishes them
// to our repo
// Publishing new packages requires 2 steps.
// 1. Upload files in a multipart/form-data request
// 2. Publish uploaded files by posting to the /packages endpoint
func UploadPackages(aadToken string, dir string, repoId string, isDebian bool) error {
	var arch string
	var fileExt string

	if isDebian {
		arch = "amd64"
		fileExt = ".deb"
	} else {
		arch = "x86_64"
		fileExt = ".rpm"
	}

	clientReqId, err := GenerateGUID()
	if err != nil {
		return fmt.Errorf("failed to generate guid for upload request: %v", err)
	}

	body := &bytes.Buffer{}
	multiWriter := multipart.NewWriter(body)
	multiWriter.WriteField("repositoryId", repoId)

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to list files in: %v", err)
	}

	// v3 endpoint supports batch uploads. All valid files in the directory
	// will be uploaded
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), fileExt) {
			f, err := os.Open(dir + "/" + file.Name())
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open %s for reading: %v\n", file.Name(), err)
				continue
			}
			defer f.Close()

			part, err := multiWriter.CreateFormFile("files", file.Name())
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create form file: %v\n", err)
				continue
			}

			n, err := io.Copy(part, f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to copy file contents: %v\n", err)
				continue
			}

			if n != file.Size() {
				fmt.Fprintf(os.Stderr, "file of size %d only had %d bytes written\n", file.Size(), n)
			}
		}
	}

	multiWriter.Close()

	req, err := http.NewRequest(http.MethodPost, repoFilesEndpoint, body)
	if err != nil {
		return fmt.Errorf("failed to construct request to files endpoint: %v", err)
	}

	// Header will be re-used for the package publish request
	header := map[string][]string{
		"Authorization":     {aadToken},
		"User-Agent":        {"keysinuse-pkghelper"},
		"Accept":            {"application/json"},
		"Content-Type":      {multiWriter.FormDataContentType()},
		"client-request-id": {clientReqId},
	}

	req.Header = header

	client := &http.Client{}

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request to %s: %v", req.URL.Path, err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		return fmt.Errorf("failed response for request to %s: %s", req.URL.Path, res.Status)
	}

	rawBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	fileUploadRes := &FileUploadRes{}
	err = json.Unmarshal(rawBody, fileUploadRes)
	if err != nil {
		return fmt.Errorf("failed to unmarshall response: %v", err)
	}

	// Files have been uploaded, call publishing endpoint
	packagePublishReq := &PackagePublishReq{
		RepositoryId: repoId,
		FileId:       fileUploadRes.UploadId,
		Packages:     []Package{},
	}

	// Filter files by architecture and rpm/debian
	for _, file := range fileUploadRes.UploadedFiles {
		trimmedFileName := strings.TrimSuffix(file.Name, "."+arch+fileExt)
		if trimmedFileName == file.Name {
			continue
		}

		nameArch := strings.SplitN(trimmedFileName, "-", 2)
		if len(nameArch) != 2 {
			continue
		}

		packagePublishReq.Packages = append(packagePublishReq.Packages, Package{
			FileName:     file.Name,
			Name:         nameArch[0],
			Version:      nameArch[1],
			Architecture: arch,
			RepositoryId: repoId,
		})
	}

	publishBody, err := json.Marshal(packagePublishReq)
	if err != nil {
		return fmt.Errorf("failed to marshal package publish request: %v", err)
	}

	body.Reset()
	_, err = body.Write(publishBody)
	if err != nil {
		return fmt.Errorf("failed to write body for package publish request: %v", err)
	}

	req, err = http.NewRequest(http.MethodPost, repoPackageEndpoint, body)
	if err != nil {
		return fmt.Errorf("failed to construct request to packages endpoint: %v", err)
	}

	req.Header = header
	req.Header.Set("Content-Type", "application/json")

	publishRes, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request to %s: %v", req.URL.Path, err)
	}
	defer publishRes.Body.Close()

	if res.StatusCode >= 300 {
		return fmt.Errorf("failed response for request to %s: %s", req.URL.Path, publishRes.Status)
	}

	return nil
}
