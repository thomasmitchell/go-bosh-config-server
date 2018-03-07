package credentials

//Value is called value by Credhub, but a value is really just a string.
// Any other JSON type results in an error
type value struct {
	contents string
}

func (v *value) ParamType() interface{} {
	return nil
}

func (v *value) ValueType() interface{} {
	return ""
}

func (v *value) Generate(interface{}) error {
	return newErrGenNotImplemented("value")
}

//BackendIn expects one key: "value"
func (v *value) BackendIn(input map[string]string) {
	v.contents = input["value"]
}

func (v *value) BackendOut() map[string]string {
	return map[string]string{"value": v.contents}
}

func (v *value) ValueIn(in interface{}) {
	v.contents = in.(string)
}

func (v *value) ValueOut() interface{} {
	return v.contents
}

func (v *value) Validate() error {
	if len(v.contents) == 0 {
		return newErrMissingKey("value")
	}

	return nil
}
