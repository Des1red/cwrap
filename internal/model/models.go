package model

type Request struct {
	Method string
	URL    string
	Flags  Flags
}

type Flags struct {
	Run     bool
	Profile string

	Headers []Header
	Cookies []Cookie
	Bearer  string

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
