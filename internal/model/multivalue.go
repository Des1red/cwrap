package model

type MultiValue []string

func (m *MultiValue) String() string {
	return ""
}

func (m *MultiValue) Set(value string) error {
	*m = append(*m, value)
	return nil
}
