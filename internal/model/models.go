package model

import (
	"os"
	"path/filepath"
)

type Request struct {
	Method        string
	URL           string
	FilePath      string
	SubdomainFile string
	ReconMode     string
	Flags         Flags
	Original      string
}

type Flags struct {
	SeedURLs []string

	Run     bool
	Profile string

	Headers []Header
	Cookies []Cookie
	Bearer  string
	CSRF    bool

	Body string
	JSON bool

	Form []FormField

	Filename string
	AsImage  string

	NoFollow bool

	Head bool

	Proxy string

	Query []QueryParam

	ContentProfile string

	Target     string
	Debug      bool
	AutoCookie bool

	// scan-specific
	DirWordlist    string // --dir
	DomainWordlist string // --domain
}

type Header struct {
	Name  string
	Value string
}

type Cookie struct {
	Name  string
	Value string
}

type FormField struct {
	Key    string
	Value  string
	IsFile bool
	Extra  string // ;type= ;filename= etc (future helpers)
}

type QueryParam struct {
	Key   string
	Value string
}

const ReportExtension = "report"
const ReportDirectoryName = "reports"

func ConfigDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.Getenv("HOME")
	}
	base := filepath.Join(dir, "cwrap")
	os.MkdirAll(base, 0755)
	return base
}
