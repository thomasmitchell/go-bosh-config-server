package internal

import (
	"encoding/json"
	"strconv"
)

//IntOrString tries to interpret a JSON string or int literal as a Go int64
type IntOrString int64

func (ios *IntOrString) UnmarshalJSON(b []byte) error {
	var i int64
	//First try to unmarshal into an int
	err := json.Unmarshal(b, &i)
	//If an error is returned, make sure its not just because we need to try a string
	if err != nil {
		if _, isTypeError := err.(*json.UnmarshalTypeError); !isTypeError {
			return err
		}

		var s string
		err = json.Unmarshal(b, &s)
		if err != nil {
			return err
		}

		i, err = strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
	}

	*ios = IntOrString(i)
	return nil
}
