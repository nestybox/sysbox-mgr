//
// Copyright: (C) 2019 - 2020 Nestybox Inc.  All rights reserved.
//

package dockerUtils

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

type DockerContainer struct {
	ImageID string
}

type Docker struct {
	cli      *client.Client
	dataRoot string
}

func DockerConnect() (*Docker, error) {

	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to Docker API: %v", err)
	}

	info, err := cli.Info(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve Docker info: %v", err)
	}

	return &Docker{
		cli:      cli,
		dataRoot: info.DockerRootDir,
	}, nil
}

func (d *Docker) GetDataRoot() string {
	return d.dataRoot
}

func (d *Docker) GetContainer(containerID string) (DockerContainer, error) {
	var dc DockerContainer

	filter := filters.NewArgs()
	filter.Add("id", containerID)

	cli := d.cli

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{
		All:     true, // required since container may not yet be running
		Filters: filter,
	})
	if err != nil {
		return dc, err
	}

	if len(containers) == 0 {
		return dc, fmt.Errorf("not found")
	} else if len(containers) > 1 {
		return dc, fmt.Errorf("more than one container matches ID %s: %v", containerID, containers)
	}

	dc.ImageID = containers[0].ImageID

	return dc, nil
}

func (d *Docker) IsDockerContainer(id string) bool {
	_, err := d.GetContainer(id)
	return err == nil
}
