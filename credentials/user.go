package credentials

import "github.com/thomasmmitchell/go-bosh-config-server/credentials/internal"

//user implements Credential and generates usernames and passwords
type user struct {
	username string
	password string
}

type userParams struct {
	//A user credential just makes a password with the same params as a username
	// So we'll just use the Password credential generator. It uses the same
	// params too
	Length         uint `json:"length"`
	ExcludeUpper   bool `json:"exclude_upper"`
	ExcludeLower   bool `json:"exclude_lower"`
	ExcludeNumber  bool `json:"exclude_number"`
	IncludeSpecial bool `json:"include_special"`
	//None of the above parameters actually seem to apply to the username.
	//Instead, Credhub always seems to make a 20 character username without
	//symbols. We'll do the same.
	Username string `json:"username"`
}

type userValue struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (u *user) ParamType() interface{} {
	return userParams{
		Length: 30,
	}
}

func (u *user) ValueType() interface{} {
	return userValue{}
}

func (u *user) Generate(in interface{}) error {
	params := in.(userParams)
	u.username = params.Username
	if u.username == "" {
		userGenerator := internal.StringGenerator{Length: 20}
		userGenerator.CharSet = append(userGenerator.CharSet, internal.Uppercase...)
		userGenerator.CharSet = append(userGenerator.CharSet, internal.Lowercase...)
		userGenerator.CharSet = append(userGenerator.CharSet, internal.Numbers...)
		var err error
		u.username, err = userGenerator.Generate()
		if err != nil {
			if _, isOurFault := err.(*internal.ErrNoStringPossible); isOurFault {
				panic("We made an invalid string generator by ourselves")
			}

			return err
		}
	}

	//Just use the Password cred code we already wrote.
	passCred := &password{}
	passCredParams := &passwordParams{
		Length:         params.Length,
		ExcludeUpper:   params.ExcludeUpper,
		ExcludeLower:   params.ExcludeLower,
		ExcludeNumber:  params.ExcludeNumber,
		IncludeSpecial: params.IncludeSpecial,
	}

	err := passCred.Generate(&passCredParams)
	if err != nil {
		return err
	}

	u.password = passCred.ValueOut().(string)
	return nil
}

//BackendIn expects "username" and "password" keys
func (u *user) BackendIn(input map[string]string) {
	u.username = input["username"]
	u.password = input["password"]
}

func (u *user) BackendOut() map[string]string {
	return map[string]string{
		"username": u.username,
		"password": u.password,
	}
}

func (u *user) ValueIn(in interface{}) {
	input := in.(userValue)
	u.username = input.Username
	u.password = input.Password
}

func (u *user) ValueOut() interface{} {
	return userValue{
		Username: u.username,
		Password: u.password,
	}
}

func (u *user) Validate() error {
	if len(u.username) == 0 {
		return newErrMissingKey("username")
	}

	if len(u.password) == 0 {
		return newErrMissingKey("password")
	}

	return nil
}
