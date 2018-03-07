package credentials

import "encoding/json"

//json as a Credhub type is called JSON, but its really just a JSON map. No
//arrays, scalars, or strings allowed
type jsonHash struct {
	hash map[string]interface{}
	//For most cred types, I can keep the API data type the same as the backend
	// storage data type, but Credhub takes JSON as an actual map, and I don't
	// want to assume that a backend can encode a multi-level map. As a result,
	// one of the input directions needs to convert JSON and therefore have a
	// way to signal to Validate if the JSON was no good
	invalid bool
}

func (j *jsonHash) ParamType() interface{} {
	return nil
}

func (j *jsonHash) ValueType() interface{} {
	return map[string]interface{}{}
}

//Generate makes no sense for a JSON hash
func (j *jsonHash) Generate(interface{}) error {
	return newErrGenNotImplemented("json")
}

//BackendIn expects one key: "json"
func (j *jsonHash) BackendIn(input map[string]string) {
	jsonKey, found := input["json"]
	if !found {
		return
	}

	j.hash = make(map[string]interface{})
	err := json.Unmarshal([]byte(jsonKey), &j.hash)
	if err != nil {
		j.invalid = true
	}
}

func (j *jsonHash) BackendOut() map[string]string {
	jsonBytes, err := json.Marshal(&j.hash)
	if err != nil {
		panic("Called BackendOut() on json credential type without initializing the contents")
	}

	return map[string]string{"json": string(jsonBytes)}
}

func (j *jsonHash) ValueIn(in interface{}) {
	j.hash = in.(map[string]interface{})
}

func (j *jsonHash) ValueOut() interface{} {
	return j.hash
}

func (j *jsonHash) Validate() error {
	if j.invalid {
		return newErrCredUnusable("json key was not a valid JSON hash")
	}

	if j.hash == nil {
		return newErrMissingKey("json")
	}

	return nil
}
