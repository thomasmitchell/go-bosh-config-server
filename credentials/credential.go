package credentials

import "fmt"

/*====================
   Credential Flow
=====================*/
//This is how you can expect the controller to call these implemented functions
//GET calls:
// BackendIn->Validate->ValueOut
//SET calls:
// ValueType->ValueIn(<ValueType>)->Validate->BackendOut->ValueOut
//GENERATE calls:
// ParamType->Generate(<ParamType>)->BackendOut->ValueOut

//Credential represents a type of credential that can go into the backend store.
//It contains functions for randomly generating a credential of this type, as
//well as accessing the values of this type. The Credential implementing object
//itself should serve as an intermediate representation of the credential data
//when moving between the storage backend, the API frontend, and brand spankin'
//new generated creds
type Credential interface {
	//ParamType should return an instance of the type that the "parameters" map
	//from incoming generate API calls should be unmarshalled into. The struct
	//should contain the desired default values for each of the fields. The
	//incoming API calls are in JSON, and therefore the struct should be
	//unmarshallable-into from JSON. If the Credential type does not support
	//generation, return nil
	ParamType() interface{}
	//ValueType should return an _instance_ of the type that the "value" map from
	//incoming set API calls should be unmarshalled into. This should also be
	//unmarshallable into JSON
	ValueType() interface{}
	//Generate generates a secret of the type that the implementing Credential
	//object represents. The result is stored in the implementing Credential
	// for serialization at a later time.
	//It receives a struct of the type returned by ParamType
	//after it has been Unmarshalled-into from the "parameters" key of an API
	//request.
	//If generating a credential of this type is not implemented, this should
	//return ErrGenNotImplemented.
	Generate(interface{} /*.(<ParamType>) */) error
	//BackendIn is given a JSON string from the storage backend, and should
	//unmarshal that information into this credential struct. The implementing
	//Credential should set its internal state such that a call to ValueOut() or
	//BackendOut() would reflect the values that in the map.
	BackendIn(map[string]string)
	//BackendOut should return a map of strings to strings to be stored in the
	//backend storage. This format should be understood by BackendIn(). Not all
	//inputs going in will be strings, but the backend code shouldn't need to
	//worry about what type you're trying to store, and it's much easier for the
	//Credential itself to know how to serialize and deserialize from(to?) strings
	BackendOut() map[string]string
	//ValueIn receives an argument of the type returned by ValueType. The
	//implementing Credential should set its internal state such that a call to
	//ValueOut() or BackendOut() would reflect the values that in the ValueType.
	ValueIn(interface{} /*.(<ValueType>)*/)
	//ValueOut returns an interface that will be JSONified and used as the "value"
	//key of a get request for this credential. This interface should be of the
	//type that is returned by ValueType
	ValueOut() interface{} /*.(ValueType)*/
	//Validate should return an error if the current internal state of the
	//Credential is somehow invalid (e.g. missing values, improperly formatted
	//values)
	Validate() error
}

/*============================
		  Credential Index
=============================*/

//Index maps the API type names to the credential struct
var Index = map[string]Credential{
	"value":       &value{},
	"json":        &jsonHash{},
	"user":        &user{},
	"password":    &password{},
	"certificate": &certificate{},
	"rsa":         &rsaPair{},
}

/*============================
  Error types for credentials
=============================*/
//The error messages from here are given to the user

//ErrGenNotImplemented is given from a call to Generate() on a Credential type
// that does not support it
type ErrGenNotImplemented struct {
	credtype string
}

func newErrGenNotImplemented(credtype string) error {
	return &ErrGenNotImplemented{credtype: credtype}
}

func (e *ErrGenNotImplemented) Error() string {
	return fmt.Sprintf("Cannot generate credentials of type `%s'", e.credtype)
}

//ErrInvalidParams is given from a call to Generate() if the params given had
// an invalid value, was missing a required parameter, or had some invalid
// combination of parameters
type ErrInvalidParams struct {
	message string
}

func newErrInvalidParams(message string) error {
	return &ErrInvalidParams{message: message}
}

func (e *ErrInvalidParams) Error() string {
	return fmt.Sprintf("Invalid parameters given: %s", e.message)
}

//ErrCredUnusable should be returned if the credential was missing required
// values or is otherwise unusable. This can be interpreted as the key missing
// values coming from the storage backend, or being for some reason unusable
// coming from a SET call
type ErrCredUnusable struct {
	message string
}

func newErrCredUnusable(message string) error {
	return &ErrCredUnusable{message: message}
}

//newErrMissingKey returns an ErrCredUnusable with a message complaining about
// the given key missing
func newErrMissingKey(key string) error {
	return &ErrCredUnusable{fmt.Sprintf("Missing key: `%s'", key)}
}

func (e *ErrCredUnusable) Error() string {
	return fmt.Sprintf("Improperly formatted credential value: %s", e.message)
}
