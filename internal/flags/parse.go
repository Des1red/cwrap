package flags

import (
	"cwrap/internal/model"
	"flag"
)

func Parse(args []string) model.Flags {

	var f model.Flags
	fs := flag.NewFlagSet("cwrap", flag.ContinueOnError)

	r := register(fs, &f)
	_ = fs.Parse(args)

	applyProfiles(&f, *r)
	normalizeBasic(&f, *r)
	normalizeForms(&f, *r)
	normalizeQuery(&f, *r)

	return f
}
