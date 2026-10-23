// Package env includes convenience functions for accessing environment variables
// and converting them to useable types.
package env

import (
	"errors"
	"os"
	"path"
	"strconv"
)

type SystemdCredentialError string

func (s SystemdCredentialError) Error() string {
	return "unable to retrieve credential: " + string(s)
}

const (
	ErrNoCredentialsDir SystemdCredentialError = "credentials directory is not set"
	ErrCredentialFile   SystemdCredentialError = "unable to read credential file"
)

func Get(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func GetInt(key string, fallback int) int {
	if val, ok := os.LookupEnv(key); ok {
		if out, err := strconv.Atoi(val); err == nil {
			return out
		}
	}
	return fallback
}

func GetBool(key string, fallback bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		if out, err := strconv.ParseBool(val); err == nil {
			return out
		}
	}
	return fallback
}

func GetSystemdCredential(name string) ([]byte, error) {
	dir, ok := os.LookupEnv("CREDENTIALS_DIRECTORY")
	if !ok {
		return nil, ErrNoCredentialsDir
	}
	b, err := os.ReadFile(path.Join(dir, name))
	if err != nil {
		return nil, errors.Join(ErrCredentialFile, err)
	}
	return b, nil
}
