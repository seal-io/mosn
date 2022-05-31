package sca

import (
	stdjson "encoding/json"

	"k8s.io/apimachinery/pkg/util/sets"
)

// mavenPackageDescriptor holds the descriptor of a maven archive.
type mavenPackageDescriptor struct {
	ChecksumAlgorithm string
	Checksum          string

	Path       string
	GroupID    string
	ArtifactID string
	Version    string
	Packaging  string

	RawData stdjson.RawMessage
}

// getName returns the name of the maven archive.
func (s mavenPackageDescriptor) getName() string {
	return s.GroupID + "/" + s.ArtifactID + ":" + s.Version
}

// getChecksum returns the checksum within type and algorithm,
// it might be blank if it does not have a checksum.
func (s mavenPackageDescriptor) getChecksum() string {
	if len(s.Checksum) < 3 {
		return ""
	}
	return "/maven/" + s.ChecksumAlgorithm + "/" + s.Checksum[:2] + "/" + s.Checksum
}

// mavenPackagingExtensionMap holds the mapping between packaging and extension,
// ref to https://maven.apache.org/ref/3.8.5/maven-core/artifact-handlers.html.
var mavenPackagingExtensionMap = map[string]string{
	"pom":          ".pom",
	"jar":          ".jar",
	"maven-plugin": ".jar",
	"ejb":          ".jar",
	"ear":          ".ear",
	"war":          ".war",
	"par":          ".par",
	"sar":          ".sar",
	"rar":          ".rar",
	"java-source":  ".jar",
	"javadoc":      ".jar",
	"jpi":          ".jpi",
	"hpi":          ".hpi",
	"lpkg":         ".lpkg",
	"bundle":       ".jar",
	"":             ".jar",
}

// mavenPackagingProcessedSet holds the packaging set which should be processed.
var mavenPackagingProcessedSet = sets.String{}

// mavenExtensionProcessedSet holds the extension set which should be processed.
var mavenExtensionProcessedSet = sets.String{}

func init() {
	for p, e := range mavenPackagingExtensionMap {
		switch p {
		case "pom", "java-source", "javadoc", "rar":
			continue
		default:
		}
		mavenPackagingProcessedSet.Insert(p)
		mavenExtensionProcessedSet.Insert(e)
	}
}
