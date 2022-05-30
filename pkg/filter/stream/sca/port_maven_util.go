package sca

import (
	stdjson "encoding/json"
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
