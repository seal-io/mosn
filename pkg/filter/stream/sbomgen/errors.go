package sbomgen

import "errors"

var errValidationEmptyEndpoint = errors.New("validation empty endpoint")

type validationBlockError struct {
	message    string
	requestURL string
}

func (e *validationBlockError) Error() string {
	return "validation block as: " + e.message
}
