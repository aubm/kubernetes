/*
Copyright 2016 The Kubernetes Authors.

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

package create

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util"
	"k8s.io/kubectl/pkg/util/hash"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	configMapLong = templates.LongDesc(i18n.T(`
		Create a configmap based on a file, directory, or specified literal value.

		A single configmap may package one or more key/value pairs.

		When creating a configmap based on a file, the key will default to the basename of the file, and the value will
		default to the file content.  If the basename is an invalid key, you may specify an alternate key.

		When creating a configmap based on a directory, each file whose basename is a valid key in the directory will be
		packaged into the configmap.  Any directory entries except regular files are ignored (e.g. subdirectories,
		symlinks, devices, pipes, etc).`))

	configMapExample = templates.Examples(i18n.T(`
		  # Create a new configmap named my-config based on folder bar
		  kubectl create configmap my-config --from-file=path/to/bar

		  # Create a new configmap named my-config with specified keys instead of file basenames on disk
		  kubectl create configmap my-config --from-file=key1=/path/to/bar/file1.txt --from-file=key2=/path/to/bar/file2.txt

		  # Create a new configmap named my-config with key1=config1 and key2=config2
		  kubectl create configmap my-config --from-literal=key1=config1 --from-literal=key2=config2

		  # Create a new configmap named my-config from the key=value pairs in the file
		  kubectl create configmap my-config --from-file=path/to/bar

		  # Create a new configmap named my-config from an env file
		  kubectl create configmap my-config --from-env-file=path/to/bar.env`))
)

// ConfigMapOptions holds properties for create configmap sub-command
type ConfigMapOptions struct {
	PrintFlags *genericclioptions.PrintFlags
	PrintObj   func(obj runtime.Object) error

	Name           string
	FileSources    []string
	LiteralSources []string
	EnvFileSource  string
	AppendHash     bool
	FieldManager   string

	Client         *corev1client.CoreV1Client
	DryRunStrategy cmdutil.DryRunStrategy
	DryRunVerifier *resource.DryRunVerifier

	genericclioptions.IOStreams
}

func NewConfigMapOptions(ioStreams genericclioptions.IOStreams) *ConfigMapOptions {
	return &ConfigMapOptions{
		PrintFlags:     genericclioptions.NewPrintFlags("created").WithTypeSetter(scheme.Scheme),
		IOStreams:      ioStreams,
		FileSources:    []string{},
		LiteralSources: []string{},
		EnvFileSource:  "",
		AppendHash:     false,
	}
}

// NewCmdCreateConfigMap initializes and returns ConfigMapOptions
func NewCmdCreateConfigMap(f cmdutil.Factory, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewConfigMapOptions(ioStreams)

	cmd := &cobra.Command{
		Use:                   "configmap NAME [--from-file=[key=]source] [--from-literal=key1=value1] [--dry-run=server|client|none]",
		DisableFlagsInUseLine: true,
		Aliases:               []string{"cm"},
		Short:                 i18n.T("Create a configmap from a local file, directory or literal value"),
		Long:                  configMapLong,
		Example:               configMapExample,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(f, cmd, args))
			cmdutil.CheckErr(o.Validate())
			cmdutil.CheckErr(o.Run())
		},
	}

	o.PrintFlags.AddFlags(cmd)

	cmdutil.AddApplyAnnotationFlags(cmd)
	cmdutil.AddValidateFlags(cmd)
	cmdutil.AddDryRunFlag(cmd)
	cmd.Flags().StringSliceVar(&o.FileSources, "from-file", o.FileSources, "Key file can be specified using its file path, in which case file basename will be used as configmap key, or optionally with a key and file path, in which case the given key will be used.  Specifying a directory will iterate each named file in the directory whose basename is a valid configmap key.")
	cmd.Flags().StringArrayVar(&o.LiteralSources, "from-literal", o.LiteralSources, "Specify a key and literal value to insert in configmap (i.e. mykey=somevalue)")
	cmd.Flags().StringVar(&o.EnvFileSource, "from-env-file", o.EnvFileSource, "Specify the path to a file to read lines of key=val pairs to create a configmap (i.e. a Docker .env file).")
	cmd.Flags().BoolVar(&o.AppendHash, "append-hash", o.AppendHash, "Append a hash of the configmap to its name.")
	cmdutil.AddFieldManagerFlagVar(cmd, &o.FieldManager, "kubectl-create")
	return cmd
}

// Complete completes all the required options
func (o *ConfigMapOptions) Complete(f cmdutil.Factory, cmd *cobra.Command, args []string) error {
	var err error
	o.Name, err = NameFromCommandArgs(cmd, args)
	if err != nil {
		return err
	}

	restConfig, err := f.ToRESTConfig()
	if err != nil {
		return err
	}
	o.Client, err = corev1client.NewForConfig(restConfig)
	if err != nil {
		return err
	}

	o.DryRunStrategy, err = cmdutil.GetDryRunStrategy(cmd)
	if err != nil {
		return err
	}
	dynamicClient, err := f.DynamicClient()
	if err != nil {
		return err
	}
	discoveryClient, err := f.ToDiscoveryClient()
	if err != nil {
		return err
	}
	o.DryRunVerifier = resource.NewDryRunVerifier(dynamicClient, discoveryClient)
	cmdutil.PrintFlagsWithDryRunStrategy(o.PrintFlags, o.DryRunStrategy)

	printer, err := o.PrintFlags.ToPrinter()
	if err != nil {
		return err
	}
	o.PrintObj = func(obj runtime.Object) error {
		return printer.PrintObj(obj, o.Out)
	}

	return nil
}

func (o *ConfigMapOptions) Validate() error {
	if len(o.Name) == 0 {
		return fmt.Errorf("name must be specified")
	}

	if len(o.EnvFileSource) > 0 && (len(o.FileSources) > 0 || len(o.LiteralSources) > 0) {
		return fmt.Errorf("from-env-file cannot be combined with from-file or from-literal")
	}

	return nil
}

// Run performs the execution of 'create' sub command options
func (o *ConfigMapOptions) Run() error {
	configMap := &v1.ConfigMap{}
	configMap.Name = o.Name
	configMap.Data = map[string]string{}
	configMap.BinaryData = map[string][]byte{}
	if err := o.handleConfigMapFromFileSources(configMap); err != nil {
		return err
	}
	if err := o.handleConfigMapFromLiteralSources(configMap); err != nil {
		return err
	}
	if err := o.handleConfigMapFromEnvFileSource(configMap); err != nil {
		return err
	}
	if o.AppendHash {
		h, err := hash.ConfigMapHash(configMap)
		if err != nil {
			return err
		}
		configMap.Name = fmt.Sprintf("%s-%s", configMap.Name, h)
	}
	return nil
}

// handleConfigMapFromFileSources adds the specified file source information
// into the provided configMap
func (o *ConfigMapOptions) handleConfigMapFromFileSources(configMap *v1.ConfigMap) error {
	if len(o.FileSources) == 0 {
		return nil
	}

	for _, fileSource := range o.FileSources {
		keyName, filePath, err := util.ParseFileSource(fileSource)
		if err != nil {
			return err
		}
		info, err := os.Stat(filePath)
		if err != nil {
			switch err := err.(type) {
			case *os.PathError:
				return fmt.Errorf("error reading %s: %v", filePath, err.Err)
			default:
				return fmt.Errorf("error reading %s: %v", filePath, err)
			}
		}
		if info.IsDir() {
			if strings.Contains(fileSource, "=") {
				return fmt.Errorf("cannot give a key name for a directory path.")
			}
			fileList, err := ioutil.ReadDir(filePath)
			if err != nil {
				return fmt.Errorf("error listing files in %s: %v", filePath, err)
			}
			for _, item := range fileList {
				itemPath := path.Join(filePath, item.Name())
				if item.Mode().IsRegular() {
					keyName = item.Name()
					err = o.addFileToConfigMap(configMap, keyName, itemPath)
					if err != nil {
						return err
					}
				}
			}
		} else {
			if err := o.addFileToConfigMap(configMap, keyName, filePath); err != nil {
				return err
			}
		}
	}

	return nil
}

// handleConfigMapFromLiteralSources adds the specified literal source
// information into the provided configMap.
func (o *ConfigMapOptions) handleConfigMapFromLiteralSources(configMap *v1.ConfigMap) error {
	for _, literalSource := range o.LiteralSources {
		keyName, value, err := util.ParseLiteralSource(literalSource)
		if err != nil {
			return err
		}
		err = o.addLiteralToConfigMap(configMap, keyName, value)
		if err != nil {
			return err
		}
	}
	return nil
}

// handleConfigMapFromEnvFileSource adds the specified env file source information
// into the provided configMap
func (o *ConfigMapOptions) handleConfigMapFromEnvFileSource(configMap *v1.ConfigMap) error {
	envFileSource := o.EnvFileSource
	if len(o.EnvFileSource) == 0 {
		return nil
	}

	info, err := os.Stat(o.EnvFileSource)
	if err != nil {
		switch err := err.(type) {
		case *os.PathError:
			return fmt.Errorf("error reading %s: %v", envFileSource, err.Err)
		default:
			return fmt.Errorf("error reading %s: %v", envFileSource, err)
		}
	}
	if info.IsDir() {
		return fmt.Errorf("env config file cannot be a directory")
	}

	return addFromEnvFile(envFileSource, func(key, value string) error {
		return o.addLiteralToConfigMap(configMap, key, value)
	})
}

// addFileToConfigMap adds a key with the given name to a ConfigMap, populating
// the value with the content of the given file path, or returns an error.
func (o *ConfigMapOptions) addFileToConfigMap(configMap *v1.ConfigMap, keyName, filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	if utf8.Valid(data) {
		return o.addLiteralToConfigMap(configMap, keyName, string(data))
	}

	err = o.validateNewConfigMap(configMap, keyName)
	if err != nil {
		return err
	}
	configMap.BinaryData[keyName] = data
	return nil
}

// addLiteralToConfigMap adds the given key and data to the given config map,
// returning an error if the key is not valid or if the key already exists.
func (o *ConfigMapOptions) addLiteralToConfigMap(configMap *v1.ConfigMap, keyName, data string) error {
	err := o.validateNewConfigMap(configMap, keyName)
	if err != nil {
		return err
	}
	configMap.Data[keyName] = data
	return nil
}

func (o *ConfigMapOptions) validateNewConfigMap(configMap *v1.ConfigMap, keyName string) error {
	// Note, the rules for ConfigMap keys are the exact same as the ones for SecretKeys.
	if errs := validation.IsConfigMapKey(keyName); len(errs) != 0 {
		return fmt.Errorf("%q is not a valid key name for a ConfigMap: %s", keyName, strings.Join(errs, ";"))
	}

	if _, exists := configMap.Data[keyName]; exists {
		return fmt.Errorf("cannot add key %q, another key by that name already exists in Data for ConfigMap %q", keyName, configMap.Name)
	}
	if _, exists := configMap.BinaryData[keyName]; exists {
		return fmt.Errorf("cannot add key %q, another key by that name already exists in BinaryData for ConfigMap %q", keyName, configMap.Name)
	}
	return nil
}
