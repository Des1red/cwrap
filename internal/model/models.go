package model

type Request struct {
	Method   string
	URL      string
	FilePath string
	Flags    Flags
	Original string
}

type Flags struct {
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

	Follow bool

	Head bool

	Proxy string

	Query []QueryParam

	ContentProfile string

	Target     string
	Debug      bool
	AutoCookie bool
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
