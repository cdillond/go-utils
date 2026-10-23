package middleware

import (
	"errors"
	"fmt"
	"net/http"
)

type Responder interface {
	Respond(http.ResponseWriter, *http.Request) error
}

type ResponderFunc func(http.ResponseWriter, *http.Request) error

func (fn ResponderFunc) Respond(w http.ResponseWriter, r *http.Request) error {
	return fn(w, r)
}

type recoverError string

func (r recoverError) Error() string { return string(r) }

const errRecovered recoverError = "recovered panic in http.Handler"

func AdaptHandler(h http.Handler) ResponderFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var err error

		defer func() {
			if rec := recover(); rec != nil {
				switch e := rec.(type) {
				case error:
					err = errors.Join(errRecovered, e)
				case string:
					err = errors.Join(errRecovered, errors.New(e))
				default:
					err = errors.Join(errRecovered, fmt.Errorf("%v", e))
				}
			}
		}()

		h.ServeHTTP(w, r)

		return err
	}
}
