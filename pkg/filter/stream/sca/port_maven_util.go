package sca

import stdjson "encoding/json"

// mavenPackageDescriptor holds the descriptor of a maven archive.
type mavenPackageDescriptor struct {
	checksumAlgorithm string
	checksum          string

	path       string
	groupID    string
	artifactID string
	version    string
	packaging  string

	rawData stdjson.RawMessage
}

// getName returns the name of the maven archive.
func (s mavenPackageDescriptor) getName() string {
	return s.groupID + "/" + s.artifactID + ":" + s.version
}

// getChecksum returns the checksum within type and algorithm,
// it might be blank if it does not have a checksum.
func (s mavenPackageDescriptor) getChecksum() string {
	if len(s.checksum) < 3 {
		return ""
	}
	return "/maven/" + s.checksumAlgorithm + "/" + s.checksum[:2] + "/" + s.checksum
}
