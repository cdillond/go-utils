package middleware

import (
	"net/http"
)

type StatusResponseWriter struct {
	http.ResponseWriter
	Status int
}

func (sw *StatusResponseWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }

func (sw *StatusResponseWriter) WriteHeader(statusCode int) {
	sw.Status = statusCode
	sw.ResponseWriter.WriteHeader(statusCode)
}

func (sw *StatusResponseWriter) Write(b []byte) (int, error) {
	if sw.Status == 0 {
		sw.Status = http.StatusOK
	}
	return sw.ResponseWriter.Write(b)
}
