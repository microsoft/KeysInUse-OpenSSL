package main

/*
#cgo amd64 LDFLAGS: -L/usr/include/openssl -lcrypto
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/safestack.h>

#define CONF_TYPE LHASH_OF(CONF_VALUE)
#define CONF_VALUE_STACK STACK_OF(CONF_VALUE)
*/
import "C"
import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"text/template"
	"unsafe"
)

type ConfigTemplate struct {
	InitSection   string
	EngineSection string
	EngineDir     string
	EngineName    string
	LoggingId     string
}

const (
	libraryDir           = "/usr/lib/keysinuse"
	configDir            = "/etc/keysinuse"
	engineName           = "keysinuse.so"
	engineConfigPath     = configDir + "/keysinuse.cnf"
	defaultInitSection   = "openssl_init"
	defaultEngineSection = "engine_section"
	loggingRoot          = "/var/log/keyinuse"
	installLogPath       = "/var/log/keysinuse/install.log"
	runningProcsPath     = "/var/log/keysinuse/running_procs.log"
	openSslConfLine      = "openssl_conf = openssl_init"

	// Only added if the engines section is not present
	templateInitSection = `[ {{.InitSection}} ]
engines = {{.EngineSection}}

`

	// Minimum config required to load the engine by config.
	// If 'update-default' is not used, then the engine can be
	// enabled manually by using the '.include' directive on the
	// generated config file.
	templateEngineConfig = `[ {{.EngineSection}} ]
keysinuse = keysinuse_section

[ keysinuse_section ]
engine_id = keysinuse
dynamic_path = {{.EngineDir}}/{{.EngineName}}
default_algorithms = RSA,EC
init = 0
logging_id = {{.LoggingId}}
`
)

func main() {
	log.SetFlags(0)

	if uid := os.Geteuid(); uid != 0 {
		log.SetOutput(os.Stderr)
		log.Fatalln("keysinuseutil must be run as root")
	}

	var updateDefaultConfig bool
	var installEngineLibrary bool
	flag.BoolVar(&updateDefaultConfig, "update-default", false, "Set to update the default OpenSSL config to include the keysinuse config")
	flag.BoolVar(&installEngineLibrary, "install-library", false, "Set to install the engine library to the default engines directory")

	flag.Parse()

	switch flag.Arg(0) {
	case "install":
		install(updateDefaultConfig, installEngineLibrary)
	case "uninstall":
		uninstall(updateDefaultConfig, installEngineLibrary)
	default:
		printUsage("Unkown command: " + flag.Arg(0))
		os.Exit(1)
	}
}

func install(updateDefaultConfig bool, installEngineLibrary bool) {
	installLog, err := os.OpenFile(installLogPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0200)
	if err != nil {
		log.SetOutput(os.Stderr)
		log.Printf("Failed to open install log: %v\n", err)
	} else {
		log.SetOutput(installLog)
		defer func() {
			installLog.Chmod(0400)
			installLog.Close()
		}()
	}

	// Double check that we're on 1.1.1
	ver := getOpenSSLVersion()
	if ver != "1.1.1" {
		log.Fatalf("Unsupported version of OpenSSL %s\n", ver)
	}

	templateValues := ConfigTemplate{
		InitSection:   defaultInitSection,
		EngineSection: defaultEngineSection,
		EngineName:    engineName,
		EngineDir:     libraryDir,
	}

	loggingId := make([]byte, 16)
	if _, err = rand.Read(loggingId); err != nil {
		log.Printf("Failed to generate unique logging Id: %v\n", err)
	} else {
		templateValues.LoggingId = hex.EncodeToString(loggingId)
	}

	addInitSection := true
	existsEngineSection := false
	existsKeysinuseEngine := false

	if installEngineLibrary {
		if enginesDir := getEnginesDir(); enginesDir != "" {
			if err = os.Symlink(libraryDir+"/"+engineName, enginesDir+"/"+engineName); err != nil {
				log.Printf("Failed to create symlink to engine library: %s", err)
			}
			templateValues.EngineDir = getEnginesDir()
		} else {
			log.Printf("Failed to find engines directory. Engine will be loaded from %s\n", templateValues.EngineDir)
		}
	}

	defaultConfigPath := getDefaultConfigPath()
	if defaultConfigPath != "" {
		conf, err := loadOpenSslConfig(defaultConfigPath)
		if err == nil {
			defer C.CONF_free(conf)

			// Check if main configuration section exists yet
			if val := getConfigValue(conf, "", "openssl_conf"); val != "" {
				templateValues.InitSection = val
				addInitSection = false
			}

			// Check for existing engines
			if val := getConfigValue(conf, templateValues.InitSection, "engines"); val != "" {
				templateValues.EngineSection = val
				existsEngineSection = true

				// Engine section might exist but be empty.
				installedEngines := getConfigValuesInSection(conf, templateValues.EngineSection)

				if len(installedEngines) > 0 {
					for _, engineSectionName := range installedEngines {
						installedEngine := getConfigValue(conf, engineSectionName, "engine_id")
						if installedEngine == "keysinuse" { // ID before open sourcing
							existsKeysinuseEngine = true
						} else {
							log.Fatalf("Engine [%s] already installed\n", installedEngine)
						}
					}

					// Bail if another engine other than keysinuse is installed
					if !existsKeysinuseEngine || len(installedEngines) > 1 {
						os.Exit(1)
					}
				}
			}
		} else {
			log.Printf("Failed to load default config: %s", err)
		}
	} else {
		log.Printf("Failed to find OpenSSL config. Could not locate OPENSSL_DIR\n")
	}

	// Generate the config specific to this engine
	if err = createEngineConfig(existsEngineSection, templateValues); err != nil {
		log.Fatalf("Failed to create engine config file: %v\n", err)
	}

	// Get any processes already using OpenSSL
	runningProcs, err := getProcsWithOpenSsl()
	if err != nil {
		log.Printf("Failed to list processes already using OpenSSL: %v\n", err)
	}

	if !existsKeysinuseEngine && updateDefaultConfig {
		// Write changes to a temporary file, including our custom config
		// Only add the init section if it doesn't exist yet
		if err = updateConfig(true, addInitSection, defaultConfigPath); err != nil {
			log.Fatalf("Failed to update OpenSSL config: %v\n", err)
		}
	}

	// OpenSSL config was successfully updated. Write list of
	// any processes using OpenSSL before we applied the change
	runningProcsFile, err := os.OpenFile(runningProcsPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0200)
	if err != nil {
		log.Fatalf("Failed open running procs file for writing: %v\n", err)
	}
	defer func() {
		runningProcsFile.Chmod(0400)
		runningProcsFile.Close()
	}()

	for procPath := range runningProcs {
		if _, err := runningProcsFile.WriteString(procPath + "\n"); err != nil {
			log.Printf("Failed to write processes to running process log: %v\n", err)
			break
		}
	}
}

func uninstall(updateDefaultConfig bool, installEngineLibrary bool) {
	if updateDefaultConfig {
		// Deconfigure engine
		defaultConfigPath := getDefaultConfigPath()
		if defaultConfigPath == "" {
			log.Fatalf("Failed to find OpenSSL config. Could not locate OPENSSL_DIR\n")
		}

		conf, err := loadOpenSslConfig(defaultConfigPath)
		if err != nil {
			log.Fatalf("Failed to load default config: %s", err)
		}
		defer C.CONF_free(conf)

		// Ensure we're even configured
		if engineId := getConfigValue(conf, "keysinuse_section", "engine_id"); engineId == "keysinuse" {
			// Only remove the openssl_conf = openssl_init section if nothing
			// but our engine is configured. That is, the engine section is the
			// only thing found under the section referenced by openssl_conf, and
			// the keysinuse engine is the only engine found in the
			// engine section
			removeInitSection := false
			if initSectionName := getConfigValue(conf, "", "openssl_conf"); initSectionName != "" {
				if initSection := getConfigValuesInSection(conf, initSectionName); len(initSection) == 1 {
					if engineSectionName := initSection["engines"]; engineSectionName != "" {
						if engineSection := getConfigValuesInSection(conf, engineSectionName); len(engineSection) == 1 {
							removeInitSection = engineSection["keysinuse"] == "keysinuse_section"
						}
					}
				}
			}

			if err = updateConfig(false, removeInitSection, defaultConfigPath); err != nil {
				log.Fatalf("Failed to update OpenSSL config: %v\n", err)
			}

		}
	}

	// Remove generated engine config
	if err := os.Remove(engineConfigPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	if installEngineLibrary {
		// Remove symlink to engine
		engineSymlink := getEnginesDir() + "/" + engineName
		if err := os.Remove(engineSymlink); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}

// Creates the config containing all values needed to enable the keysinuse engine
func createEngineConfig(existsEngineSection bool, templateValues ConfigTemplate) error {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to config dir at %s: %v", configDir, err)
	}

	engineConfig, err := os.OpenFile(engineConfigPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer engineConfig.Close()

	if !existsEngineSection {
		tmpl, err := template.New("InitSection").Parse(templateInitSection)
		if err != nil {
			return fmt.Errorf("failed to generate template of init section in engine config: %v", err)
		}
		if err = tmpl.Execute(engineConfig, templateValues); err != nil {
			return fmt.Errorf("failed to populate init section of engine config: %v", err)
		}
	}

	tmpl, err := template.New("EngineConfig").Parse(templateEngineConfig)
	if err != nil {
		return fmt.Errorf("failed to generate template of engine config: %v", err)
	}
	if err = tmpl.Execute(engineConfig, templateValues); err != nil {
		return fmt.Errorf("failed to populate engine config: %v", err)
	}
	return nil
}

// Creates a temporary file with an updated OpenSSL config. This file will be renamed
// to overwrite the existing config atomically.
func updateConfig(isInstall bool, addRemoveInitSection bool, defaultConfigPath string) (err error) {
	tmpConfigPath := defaultConfigPath + ".tmp"

	defaultConfig, err := os.OpenFile(defaultConfigPath, os.O_RDONLY, 0)
	if err != nil {
		err = fmt.Errorf("failed to open default OpenSSL config: %v", err)
		return
	}
	defer defaultConfig.Close()

	configStat, err := defaultConfig.Stat()
	if err != nil {
		err = fmt.Errorf("failed to stat default OpenSSL config: %v", err)
		return
	}

	tmpConfig, err := os.OpenFile(tmpConfigPath, os.O_WRONLY|os.O_CREATE, configStat.Mode())
	if err != nil {
		err = fmt.Errorf("failed to create file in temporary location: %v", err)
		return
	}
	defer func() {
		tmpConfig.Close()
		os.Remove(tmpConfigPath)
	}()

	isDefaultSection := true
	s := bufio.NewScanner(defaultConfig)

	// Insert into the default section. Write line by line until
	// the first section is found. Add the necessary entries and
	// finish copying the file contents
	lineNum := 1
	wasLastLineRemoved := false
	for s.Scan() {
		line := s.Text()

		if isDefaultSection {
			trimmedLine := strings.TrimSpace(line)
			if !isInstall {
				if addRemoveInitSection && trimmedLine == openSslConfLine ||
					trimmedLine == ".include "+engineConfigPath ||
					wasLastLineRemoved && line == "" { // Remove our trailing whitespace
					wasLastLineRemoved = true
					continue
				}
				wasLastLineRemoved = false
			}

			// Found the end of the default section
			// This is where we write on install, and
			// stop checking for uninstall
			if len(trimmedLine) > 0 &&
				trimmedLine[0] == '[' {
				isDefaultSection = false

				if isInstall {
					if addRemoveInitSection {
						tmpConfig.WriteString(openSslConfLine + "\n\n")
					}
					tmpConfig.WriteString(".include " + engineConfigPath + "\n\n")
				}
			}
		}

		if _, err = tmpConfig.WriteString(line + "\n"); err != nil {
			err = fmt.Errorf("failed to copy line %d from original config: %v", lineNum, err)
			return
		}
		lineNum++
	}

	// Reached the end of the original file without finding another section
	if isDefaultSection && isInstall {
		if addRemoveInitSection {
			tmpConfig.WriteString(openSslConfLine + "\n\n")
		}
		tmpConfig.WriteString(".include " + engineConfigPath + "\n\n")
	}

	if err = os.Rename(tmpConfigPath, defaultConfigPath); err != nil {
		err = fmt.Errorf("failed to swap temporary OpenSSL config: %v", err)
	}
	return
}

// Crawls the '/proc' directory to list all processes with OpenSSL loaded
// We use a map as a simple way to avoid duplicates
func getProcsWithOpenSsl() (matchedProcs map[string]struct{}, err error) {
	matchedProcs = make(map[string]struct{})
	if procDirs, err := ioutil.ReadDir("/proc"); err == nil {
		for _, procDir := range procDirs {
			// Filter to process directories (organized by numeric PID)
			if procDir.IsDir() && regexp.MustCompile(`\d+`).MatchString(procDir.Name()) {
				procPath, err := os.Readlink("/proc/" + procDir.Name() + "/exe")
				if err != nil || strings.Contains(procPath, "keysinuseutil") {
					continue
				}

				if _, ok := matchedProcs[procPath]; ok {
					continue
				}

				filesDir := "/proc/" + procDir.Name() + "/map_files"
				openFiles, err := ioutil.ReadDir(filesDir)
				if err != nil {
					break
				}

				for _, openFile := range openFiles {
					if symLink, err := os.Readlink(filesDir + "/" + openFile.Name()); err == nil && strings.Contains(symLink, "libcrypto") {
						matchedProcs[procPath] = struct{}{}
						break
					}
				}
			}
		}
	}

	return
}

//
// Utility functions
//
func printUsage(errorMsg string) {
	log.SetOutput(os.Stderr)
	log.Println(errorMsg)
	log.SetOutput(os.Stdout)
	log.Println("keysinuseutil <command>")
	log.Println("	install: Enables keysinuse engine through global Openssl config")
	log.Println("	uninstall: Disables keysinuse engine through global Openssl config")
}

func getOpenSSLVersion() string {
	rawVersion := C.OpenSSL_version_num()

	return fmt.Sprintf("%d.%d.%d",
		(rawVersion&0xF0000000)>>28, // Major
		(rawVersion&0x0FF00000)>>20, // Minor
		(rawVersion&0x000FF000)>>12) // Patch
}

func getDefaultConfigPath() string {
	// Output of form: OPENSSLDIR: "..."
	defaultConfigPath := C.GoString(C.OpenSSL_version(C.OPENSSL_DIR))
	defaultConfigPath = strings.TrimSpace(defaultConfigPath)
	defaultConfigPath = strings.TrimPrefix(defaultConfigPath, "OPENSSLDIR: \"")
	defaultConfigPath = strings.TrimSuffix(defaultConfigPath, "\"")
	defaultConfigPath += "/openssl.cnf"

	return resolveSymLink(defaultConfigPath)
}

func getEnginesDir() string {
	// Output of form: ENGINESDIR: "..."
	engineDir := C.GoString(C.OpenSSL_version(C.OPENSSL_ENGINES_DIR))
	engineDir = strings.TrimSpace(engineDir)
	engineDir = strings.TrimPrefix(engineDir, "ENGINESDIR: \"")
	engineDir = strings.TrimSuffix(engineDir, "\"")

	return resolveSymLink(engineDir)
}

func loadOpenSslConfig(configPath string) (*C.CONF_TYPE, error) {
	var eline C.long
	path := C.CString(configPath)
	defer C.free(unsafe.Pointer(path))

	conf := C.CONF_load(nil, path, &eline)
	if conf == nil {
		return nil, errors.New(lastOpenSSLError())
	}

	return conf, nil
}

func resolveSymLink(path string) string {
	var err error
	link := path
	for path, err = os.Readlink(path); err == nil; path, err = os.Readlink(path) {
		link = path
	}
	return link
}

func lastOpenSSLError() string {
	return C.GoString(
		C.ERR_reason_error_string(C.ERR_get_error()),
	)
}

func getConfigValue(conf *C.CONF_TYPE, group string, key string) string {
	groupCString := C.CString(group)
	keyCString := C.CString(key)

	defer func() {
		C.free(unsafe.Pointer(groupCString))
		C.free(unsafe.Pointer(keyCString))
	}()

	valCString := C.CONF_get_string(conf, groupCString, keyCString)
	if valCString == nil {
		return ""
	}

	return C.GoString(valCString)
}

func getConfigValuesInSection(conf *C.CONF_TYPE, group string) map[string]string {
	configValues := make(map[string]string)
	groupCString := C.CString(group)

	defer func() {
		C.free(unsafe.Pointer(groupCString))
	}()

	section := C.CONF_get_section(conf, groupCString)
	if section != nil {
		numElems := C.sk_CONF_VALUE_num(section)
		for i := C.int(0); i < numElems; i++ {
			confValue := C.sk_CONF_VALUE_value(section, i)
			key := C.GoString(confValue.name)
			if key != "" {
				configValues[key] = C.GoString(confValue.value)
			}
		}
	}

	return configValues
}
