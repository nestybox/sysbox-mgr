//
// Copyright: (C) 2019 - 2020 Nestybox Inc.  All rights reserved.
//

package dockerUtils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestDockerUtils(t *testing.T) {
	docker, err := DockerConnect()
	if err != nil {
		t.Fatalf("DockerConnect() failed: %v", err)
	}

	dataRoot := docker.GetDataRoot()
	if dataRoot != "/var/lib/docker" {
		t.Errorf("docker.GetDataRoot(): want /var/lib/docker; got %s", dataRoot)
	}

	id, err := testStartContainer()
	if err != nil {
		t.Fatalf("Failed to start test container: %v", err)
	}

	if !docker.IsDockerContainer(id) {
		t.Errorf("IsDockerContainer(%s) failed", id)
	}

	if _, err := docker.GetContainer(id); err != nil {
		t.Errorf("GetContainer(%s) failed: %v", id, err)
	}

	if err := testStopContainer(id); err != nil {
		t.Errorf("Failed to stop test container: %v", err)
	}
}

func testStartContainer() (string, error) {
	var cmd *exec.Cmd
	var stdout, stderr bytes.Buffer

	cmd = exec.Command("docker", "run", "-d", "alpine", "tail", "-f", "/dev/null")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to start test container: %s %s\n", stdout.String(), stderr.String())
	}

	id := strings.TrimSuffix(stdout.String(), "\n")
	return id, nil
}

func testStopContainer(id string) error {
	var cmd *exec.Cmd
	var stdout, stderr bytes.Buffer

	cmd = exec.Command("docker", "stop", "-t0", id)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to stop test container: %s %s\n", stdout.String(), stderr.String())
	}

	return nil
}
