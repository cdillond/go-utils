package middleware

import "net/http"

type Responder interface {
	Respond(http.ResponseWriter, *http.Request) error
}

type ResponderFunc func(http.ResponseWriter, *http.Request) error

func (fn ResponderFunc) Respond(w http.ResponseWriter, r *http.Request) error {
	return fn(w, r)
}
