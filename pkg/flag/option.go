package options

import(
	"flag"
)

type Option struct {
	File string
	Decrypt bool
	Encrypt bool
	Output string
	App string
	Show bool
}

func GetFlag() Option {
	opt := Option{}
	flag.StringVar(&opt.File, "f", "", "file name")
	flag.StringVar(&opt.Output, "o", "", "output file name")
	flag.StringVar(&opt.App, "a", "", "name name")
	flag.BoolVar(&opt.Decrypt, "d", false, "decrypt")
	flag.BoolVar(&opt.Encrypt, "e", false, "encrypt")
	flag.BoolVar(&opt.Show, "s", false, "show decrypt file content")
	flag.Parse()

	return opt
}
