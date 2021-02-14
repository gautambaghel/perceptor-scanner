/*
Copyright (C) 2018 Synopsys, Inc.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
*/

package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/blackducksoftware/hub-client-go/hubclient"
	"github.com/juju/errors"
	log "github.com/sirupsen/logrus"
)

// DownloadDIClient tries to download the Docker Inspector client
func DownloadDIClient(osType OSType, cliRootPath string, hubScheme string, hubHost string, hubUser string, hubPassword string, hubPort int, timeout time.Duration, baseRepoURL string, dIVersionConstant string) (*DockerInspectorInfo, error) {

	// ALL THIS TO GET THE HUB VERSION - NEEDED TO FIND JAVA THAT CAME WITH SCAN CLI
	// 1. instantiate hub client
	hubBaseURL := fmt.Sprintf("%s://%s:%d", hubScheme, hubHost, hubPort)
	hubClient, err := hubclient.NewWithSession(hubBaseURL, hubclient.HubClientDebugTimings, timeout)
	if err != nil {
		return nil, errors.Annotatef(err, "DI: unable to instantiate hub client")
	}

	log.Infof("DI: successfully instantiated hub client %s", hubBaseURL)

	// 2. log in to hub client
	err = hubClient.Login(hubUser, hubPassword)
	if err != nil {
		return nil, errors.Annotatef(err, "unable to log in to hub")
	}

	log.Info("DI: successfully logged in to hub")

	// 3. get hub version
	currentVersion, err := hubClient.CurrentVersion()
	if err != nil {
		return nil, errors.Annotatef(err, "unable to get hub version")
	}

	log.Infof("DI: got hub version: %s", currentVersion.Version)

	// 4. ping artifactory to get latest DI
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/storage/bds-integrations-release/com/synopsys/integration/blackduck-docker-inspector?properties=%s", baseRepoURL, dIVersionConstant)

	log.Infof("DI: Trying to get the latest docker inspector from %s", url)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("DI: Error in pinging artifactory server %e", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	pingResponseString := ""
	if resp.StatusCode == http.StatusOK {
		respBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		pingResponseString = string(respBytes)
	} else {
		return nil, errors.New("DI: ping response not OK")
	}

	// 5. Extract Jar URL info from response
	jarURL := ""
	if pingResponseString != "" {
		// remove space
		noSpaceRespStr := strings.Join(strings.Fields(pingResponseString), "")

		// extract jar url
		re := regexp.MustCompile(`\[([^\[\]]*)\]`)
		submatchall := re.FindAllString(noSpaceRespStr, -1)
		for _, jarURL = range submatchall {
			jarURL = strings.Trim(jarURL, "[")
			jarURL = strings.Trim(jarURL, "]")
		}

		// remove quotes
		jarURL = jarURL[1 : len(jarURL)-1]
	}

	log.Infof("DI: Latest version of docker inspector downloading from %s", jarURL)
	// 6. Download DI Jar file
	diInfo := NewDockerInspectorInfo(dIVersionConstant, baseRepoURL, cliRootPath, currentVersion.Version)
	err = os.MkdirAll(diInfo.RootPath, 0755)
	if err != nil {
		return nil, errors.Annotatef(err, "DI: unable to make dir for DI %s", diInfo.RootPath)
	}

	if jarURL == "" {
		return nil, errors.New("DI: Jar URL is empty, something went wrong while retieving DI jar URL")
	}

	downloadPath := diInfo.DockerInspectorJarPath()
	log.Infof("DI: Storing jar at %s", downloadPath)
	downloadDIJar(downloadPath, jarURL)

	// 7. we're done
	return diInfo, nil
}

// DownloadScanClient downloads the Black Duck scan client
func DownloadScanClient(osType OSType, cliRootPath string, hubScheme string, hubHost string, hubUser string, hubPassword string, hubPort int, timeout time.Duration) (*ScanClientInfo, error) {
	// 1. instantiate hub client
	hubBaseURL := fmt.Sprintf("%s://%s:%d", hubScheme, hubHost, hubPort)
	hubClient, err := hubclient.NewWithSession(hubBaseURL, hubclient.HubClientDebugTimings, timeout)
	if err != nil {
		return nil, errors.Annotatef(err, "unable to instantiate hub client")
	}

	log.Infof("successfully instantiated hub client %s", hubBaseURL)

	// 2. log in to hub client
	err = hubClient.Login(hubUser, hubPassword)
	if err != nil {
		return nil, errors.Annotatef(err, "unable to log in to hub")
	}

	log.Info("successfully logged in to hub")

	// 3. get hub version
	currentVersion, err := hubClient.CurrentVersion()
	if err != nil {
		return nil, errors.Annotatef(err, "unable to get hub version")
	}

	log.Infof("got hub version: %s", currentVersion.Version)

	cliInfo := NewScanClientInfo(currentVersion.Version, cliRootPath, osType)

	// 4. create directory
	err = os.MkdirAll(cliInfo.RootPath, 0755)
	if err != nil {
		return nil, errors.Annotatef(err, "unable to make dir %s", cliInfo.RootPath)
	}

	// 5. pull down scan client as .zip
	switch osType {
	case OSTypeMac:
		err = hubClient.DownloadScanClientMac(cliInfo.ScanCliZipPath())
	case OSTypeLinux:
		err = hubClient.DownloadScanClientLinux(cliInfo.ScanCliZipPath())
	}
	if err != nil {
		return nil, errors.Annotatef(err, "unable to download scan client")
	}

	log.Infof("successfully downloaded scan client to %s", cliInfo.ScanCliZipPath())

	// 6. unzip scan client
	err = unzip(cliInfo.ScanCliZipPath(), cliInfo.RootPath)
	if err != nil {
		return nil, errors.Annotatef(err, "unable to unzip %s", cliInfo.ScanCliZipPath())
	}
	log.Infof("successfully unzipped from %s to %s", cliInfo.ScanCliZipPath(), cliInfo.RootPath)

	// 7. we're done
	return cliInfo, nil
}

func downloadDIJar(filepath string, url string) error {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}
