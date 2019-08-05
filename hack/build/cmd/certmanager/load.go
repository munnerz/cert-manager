/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certmanager

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	"github.com/jetstack/cert-manager/hack/build/cmd/options"
	"github.com/jetstack/cert-manager/hack/build/internal/bazel"
	"github.com/jetstack/cert-manager/hack/build/internal/cluster"
	logf "github.com/jetstack/cert-manager/hack/build/internal/log"
	"github.com/jetstack/cert-manager/hack/build/internal/util"
)

func RegisterLoadCmd(rootOpts *options.Root, cmOpts *options.CertManager, rootCmd *cobra.Command) {
	log := logf.Log.WithName("load")

	opts := &options.CertManagerLoad{}
	cmd := &cobra.Command{
		Use:   "load",
		Short: "Load images into the kind testing cluster",
		Run: func(cmd *cobra.Command, args []string) {
			cl := &cluster.Cluster{
				KindClusterName: opts.KindClusterName,
				Log:             log.V(4),
			}
			if rootOpts.Debug {
				cl.Stdout = os.Stdout
			}
			var wg sync.WaitGroup
			for _, component := range cmOpts.Components {
				wg.Add(1)
				nameCh := make(chan string)
				go func(component string) {
					defer close(nameCh)
					log := log.WithValues("component", component)

					log.Info("building docker image")
					ctx := context.Background()
					imageName, err := buildAndExport(ctx, log, rootOpts.RepoRoot, rootOpts.Debug, cmOpts.DockerRepo, component, cmOpts.AppVersion)
					if err != nil {
						log.Error(err, "error building image")
						os.Exit(1)
					}
					nameCh <- imageName
					log.Info("built and exported docker image")
				}(component)
				go func() {
					defer wg.Done()
					imageName := <-nameCh

					if err := cl.Load(imageName); err != nil {
						log.Error(err, "failed to load docker image into kind container")
						os.Exit(1)
					}

					log.Info("loaded docker image", "image_name", imageName)
				}()
			}
			wg.Wait()
			log.Info("loaded all images")
		},
	}
	opts.AddFlags(cmd.Flags())

	rootCmd.AddCommand(cmd)
}

func buildAndExport(ctx context.Context, log logr.Logger, repoRoot string, debug bool, dockerRepo, component, appVersion string) (string, error) {
	imageName := fmt.Sprintf("%s/cert-manager-%s:%s", dockerRepo, component, appVersion)
	ref, err := util.GitCommitRef()
	if err != nil {
		return "", fmt.Errorf("error getting git commit ref: %v", err)
	}

	log.Info("determined git commit ref", "git_commit_ref", ref)

	ci := &bazel.ContainerImage{
		Target:       "//cmd/" + component + ":image",
		WorkspaceDir: repoRoot,
		Log:          log.V(4),
		EnvVars: map[string]string{
			"DOCKER_REPO":    dockerRepo,
			"APP_VERSION":    appVersion,
			"APP_GIT_COMMIT": ref,
		},
	}
	if debug {
		ci.Stdout = os.Stdout
	}

	if err := ci.Export(ctx, imageName); err != nil {
		return "", fmt.Errorf("failed to export image")
	}

	return imageName, nil
}