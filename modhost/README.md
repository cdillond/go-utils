## Overview
`modhost` implements a server that responds to http requests with a page that contains an html meta tag indicating where the content of the requested module is hosted.


## Setup
`modhost` reads a JSON array of `Project` objects from the path specified by the `PROJECTS_PATH` environment variable. If that variable is not set, it falls back to `/etc/go-mod-host`. Changes to this file are monitored by `modhost` and are automatically reflected in its outputs. 


An example configuration file could look like this:

```json
[
    {
        "importPrefix": "go.ciaran.lol",
        "vcs": "git",
        "repoRoot": "https://github.com/cdillond/go-utils",
        "subDir": "middleware",
        "humanRedirect": "https://ciaran.lol"
    }
]

```

The `humanRedirect` field optionally specifies a URL to redirect requests that do not include a `"go-get=1"` query parameter. The `subDir` field is only available for go versions `1.25` and above, and is only used for multi-module repositories.

To specify which address the server should listen on, set `ADDR_HOST` and `ADDR_PORT` environment variables to the desired host or port, respectively. If `ADDR_HOST` is unspecified, `modhost` listens on all http interfaces. If `ADDR_PORT` is unspecified, it falls back to `8080`.

