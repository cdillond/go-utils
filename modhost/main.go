package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"go.ciaran.lol/env"
	"go.ciaran.lol/middleware"

	"bytes"
	_ "embed"
	"encoding/json/v2"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	_ "unsafe"
)

//go:embed page.html.tmpl
var page string

type Project struct {
	ImportPrefix string `json:"importPrefix"`
	Vcs          string `json:"vcs"`
	RepoRoot     string `json:"repoRoot"`
	SubDir       string `json:"subDir"`
	// HumanRedirect optionally specifies a URL to redirect requests that do not include a "go-get=1" query parameter.
	HumanRedirect string `json:"humanRedirect"`
}

func (p Project) Validate() error {
	before, after, found := strings.Cut(p.ImportPrefix, ".")
	if !found {
		return fmt.Errorf("import prefix name must contain a dot: %s", p.ImportPrefix)
	}
	if before == "" || after == "" {
		return fmt.Errorf("invalid prefix name: %s", p.ImportPrefix)
	}
	if before == "test" || before == "example" {
		return fmt.Errorf("invalid prefix name: go-mod-import will not resolve packages beginning with %s", before)
	}

	switch p.Vcs {
	case "fossil", "git", "hg", "svn":
	default:
		return fmt.Errorf("unsupported vcs: %s", p.Vcs)
	}

	u, err := url.Parse(p.RepoRoot)
	if err != nil {
		return fmt.Errorf("invalid repo root: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("invalid repo root scheme (https is required): %s", u.Scheme)
	}

	return nil
}

type ParseError struct {
	path  string
	cause error
}

func (p *ParseError) Unwrap() error {
	return p.cause
}

func (p *ParseError) Error() string {
	return fmt.Sprintf("unable to parse projects at %s: %s", p.path, p.cause.Error())
}

func parseProjects(path string) ([]Project, error) {
	var (
		f   *os.File
		err error
		out []Project
	)

	if f, err = os.Open(path); err != nil {
		return nil, &ParseError{path, err}
	}

	defer func() {
		_ = f.Close()
	}()

	if err = json.UnmarshalRead(f, &out); err != nil {
		return nil, &ParseError{path, err}
	}

	return out, nil
}

type storeError struct {
	errors []error
}

func (s *storeError) Error() string {
	return "unable to store project"
}

type cacheVal struct {
	redirect string
	b        []byte
}

type PageCache struct {
	rwm  sync.RWMutex
	t    *template.Template
	data map[string]cacheVal
}

func (m *PageCache) store(path string) error {
	m.rwm.Lock()
	defer m.rwm.Unlock()

	projects, err := parseProjects(path)
	if err != nil {
		return err
	}

	m.data = make(map[string]cacheVal, len(projects))

	var errs []error

	for _, p := range projects {
		if err = p.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		buf := new(bytes.Buffer)
		if err = m.t.Execute(buf, p); err != nil {
			errs = append(errs, fmt.Errorf("unable to render project %s: %w", p.ImportPrefix, err))
			continue
		}
		m.data[p.ImportPrefix] = cacheVal{p.HumanRedirect, buf.Bytes()}
	}

	if len(errs) == 0 {
		return nil
	}

	return &storeError{errs}
}

func (m *PageCache) clear() {
	m.rwm.Lock()
	defer m.rwm.Unlock()
	clear(m.data)
}

func (m *PageCache) load(s string) (cacheVal, bool) {
	m.rwm.RLock()
	defer m.rwm.RUnlock()

	val, ok := m.data[s]

	return val, ok
}

func watch(path string, watcher *fsnotify.Watcher, m *PageCache, logger *slog.Logger, out chan error) {
	defer close(out)

	var err error

	path = filepath.Clean(path)

	if err = watcher.Add(filepath.Dir(path)); err != nil {
		out <- fmt.Errorf("unable to watch file: %w", err)
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if event.Name != path {
				continue
			}

			if event.Has(fsnotify.Write | fsnotify.Create) {
				err = m.store(path)

				if err != nil {
					// we log these errors instead of aborting because some
					// may be transitory due to the nature of fsnotify
					if pe, ok := errors.AsType[*ParseError](err); ok {
						logger.Warn("file store error", "err", pe.Error())
					} else if se, ok := errors.AsType[*storeError](err); ok {
						for _, err = range se.errors {
							logger.Error("project store error", "err", err.Error())
						}
					} else {
						out <- fmt.Errorf("unexpected error storing projects: %w", err)
					}
				} else {
					logger.Info("reloaded projects", "path", path)
				}

			} else if event.Has(fsnotify.Remove | fsnotify.Rename) {
				m.clear()
				logger.Warn("page cache cleared", "path", path)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}

			out <- fmt.Errorf("error watching source file: %w", err)
			return
		}
	}
}

type ProjectServer struct {
	cache PageCache
}

func (s *ProjectServer) Respond(w http.ResponseWriter, r *http.Request) error {
	host := (&url.URL{Host: r.Host}).Hostname()
	path := r.PathValue("name")

	name := host + "/" + path

	proj, ok := s.cache.load(name)
	if !ok {
		http.NotFound(w, r)
		return nil
	}

	if proj.redirect != "" && r.URL.Query().Get("go-get") != "1" {
		// we want to avoid redirect cycles and invalid urls.
		u, err := url.Parse(proj.redirect)
		if err == nil {
			if !(u.Host == r.Host && u.Path == r.URL.Path) {
				http.Redirect(w, r, proj.redirect, http.StatusTemporaryRedirect)
				return nil
			}
		}
	}

	_, err := w.Write(proj.b)
	return err
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) error {
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	return nil
}

func main() {
	var (
		err         error
		server      ProjectServer
		watcher     *fsnotify.Watcher
		ctx, cancel = context.WithCancel(context.Background())
		watchCh     = make(chan error)
		httpCh      = make(chan error)
		addrHost    = env.Get("ADDR_HOST", "")
		addrPort    = env.Get("ADDR_PORT", "8080")
		path        = env.Get("PROJECTS_PATH", "/etc/go-mod-host")
		logger      = middleware.NewRequestLogger(slog.Default())
	)

	defer cancel()

	if server.cache.t, err = template.New("page").Parse(page); err != nil {
		logger.ErrorContext(ctx, "failed to parse template", "err", err)
		os.Exit(1)
	}

	if err = server.cache.store(path); err != nil {
		if se, ok := errors.AsType[*storeError](err); ok {
			for _, err = range se.errors {
				logger.ErrorContext(ctx, "failed to initialize projects", "err", err.Error())
			}
		} else {
			logger.ErrorContext(ctx, "failed to initialize projects", "err", err.Error())
		}

		os.Exit(1)
	}

	if watcher, err = fsnotify.NewWatcher(); err != nil {
		logger.ErrorContext(ctx, "failed to initialize fsnotify watcher", "err", err)
		os.Exit(1)
	}

	defer watcher.Close()

	go watch(path, watcher, &server.cache, &logger.Logger, watchCh)

	go func() {
		var mux http.ServeMux

		mux.Handle("/", logger.LogRequest(middleware.ResponderFunc(methodNotAllowed)))
		mux.Handle("GET /{name...}", logger.LogRequest(&server))

		httpCh <- http.ListenAndServe(net.JoinHostPort(addrHost, addrPort), &mux)
	}()

	select {
	case <-ctx.Done():
		logger.ErrorContext(ctx, "context canceled", "err", ctx.Err())
	case err = <-httpCh:
		logger.ErrorContext(ctx, "http server error", "err", err)
	case err, _ = <-watchCh:
		if err != nil {
			logger.ErrorContext(ctx, "fsnotify error", "err", err)
		} else {
			logger.ErrorContext(ctx, "fsnotify watch completed unexpectedly")
		}
	}

}
