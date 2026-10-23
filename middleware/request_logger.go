package middleware

import (
	"log/slog"
	"net/http"
	"uuid"
)

type RequestLogger struct {
	slog.Logger
	GroupFn func(r *http.Request) slog.Attr
}

// Returns a new logger with the [DefaultRequestGroup] as the GroupFn.
func NewRequestLogger(l *slog.Logger) RequestLogger {
	return RequestLogger{
		Logger:  *l,
		GroupFn: DefaultRequestGroup,
	}
}

func DefaultRequestGroup(r *http.Request) slog.Attr {
	return slog.GroupAttrs("request",
		slog.String("id", uuid.NewV4().String()),
		slog.String("host", r.Host),
		slog.String("path", r.URL.Path),
		slog.String("method", r.Method),
		slog.String("addr", r.RemoteAddr),
		slog.String("forwarded_for", r.Header.Get("X-Forwarded-For")),
	)
}

func (l *RequestLogger) LogRequest(next Responder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		logger := &l.Logger

		if l.GroupFn != nil {
			logger = logger.With(l.GroupFn(r))
		}

		logger.Log(ctx, slog.LevelInfo, "received")

		sw := StatusResponseWriter{ResponseWriter: w}

		if err := next.Respond(&sw, r); err != nil {
			logger.LogAttrs(ctx, slog.LevelError, "response failed", slog.String("err", err.Error()))
			return
		}

		if sw.Status == 0 {
			logger.LogAttrs(ctx, slog.LevelWarn, "response not written")
			return
		}

		status := slog.Int("status", sw.Status)
		text := http.StatusText(sw.Status)
		if text == "" {
			logger.LogAttrs(ctx, slog.LevelError, "request completed with invalid status code", status)
			return
		}

		var level slog.Level

		switch {
		case sw.Status >= 400 && sw.Status < 500:
			level = slog.LevelWarn
		case sw.Status >= 500 && sw.Status < 600:
			level = slog.LevelError
		default:
			// log at slog.LevelInfo
		}

		logger.LogAttrs(ctx, level, text, status)
	}
}
