/*
Copyright (C) 2020 Synopsys, Inc.

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

import "fmt"

// DockerInspectorInfo ...
type DockerInspectorInfo struct {
	DockerInspectorVersion string
	BaseRepoURL            string
	RootPath               string
	HubVersion             string
	OSType                 OSType
}

// NewDockerInspectorInfo ...
func NewDockerInspectorInfo(dockerInspectorVersion string, baseRepoURL string, rootPath string) *DockerInspectorInfo {
	return &DockerInspectorInfo{DockerInspectorVersion: dockerInspectorVersion, BaseRepoURL: baseRepoURL, RootPath: rootPath}
}

// DockerInspectorJarPath ...
func (sci *DockerInspectorInfo) DockerInspectorJarPath() string {
	return fmt.Sprintf("%s/dockerinspector-%s.jar", sci.RootPath, sci.DockerInspectorVersion)
}

// DockerInspectorJavaPath ...
func (sci *DockerInspectorInfo) DockerInspectorJavaPath() string {
	switch sci.OSType {
	case OSTypeLinux:
		return fmt.Sprintf("%s/scan.cli-%s/jre/bin/java", sci.RootPath, sci.HubVersion)
	case OSTypeMac:
		return fmt.Sprintf("%s/scan.cli-%s/jre/Contents/Home/bin/java", sci.RootPath, sci.HubVersion)
	}
	panic(fmt.Errorf("invalid os type: %d", sci.OSType))
}
