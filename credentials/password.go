package credentials

import "github.com/thomasmmitchell/go-bosh-config-server/credentials/internal"

//Password implements Credential and generates passwords
type password struct {
	password string
}

type passwordParams struct {
	Length         uint `json:"length"`
	ExcludeUpper   bool `json:"exclude_upper"`
	ExcludeLower   bool `json:"exclude_lower"`
	ExcludeNumber  bool `json:"exclude_number"`
	IncludeSpecial bool `json:"include_special"`
}

func (p *password) ParamType() interface{} {
	return passwordParams{Length: 30}
}

func (p *password) ValueType() interface{} {
	return ""
}

func (p *password) Generate(params interface{}) error {
	prm := params.(passwordParams)

	stringGenerator := internal.StringGenerator{Length: prm.Length}

	if !prm.ExcludeUpper {
		stringGenerator.CharSet = append(stringGenerator.CharSet, internal.Uppercase...)
	}

	if !prm.ExcludeLower {
		stringGenerator.CharSet = append(stringGenerator.CharSet, internal.Lowercase...)
	}

	if !prm.ExcludeNumber {
		stringGenerator.CharSet = append(stringGenerator.CharSet, internal.Numbers...)
	}

	if prm.IncludeSpecial {
		stringGenerator.CharSet = append(stringGenerator.CharSet, internal.Symbols...)
	}

	generated, err := stringGenerator.Generate()
	if _, paramsWereBad := err.(*internal.ErrNoStringPossible); paramsWereBad {
		err = newErrInvalidParams("A password cannot be generated with the character combination given")
	}

	p.password = generated

	return err
}

//BackendIn expects one key: "password"
func (p *password) BackendIn(input map[string]string) {
	p.password = input["password"]
}

func (p *password) BackendOut() map[string]string {
	return map[string]string{"password": p.password}
}

func (p *password) ValueIn(in interface{}) {
	p.password = in.(string)
}

func (p *password) ValueOut() interface{} {
	return p.password
}

func (p *password) Validate() error {
	if len(p.password) == 0 {
		return newErrMissingKey("password")
	}

	return nil
}
