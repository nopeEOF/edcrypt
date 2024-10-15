package main

import (
	encryption "EDCrypt/pkg/enc"
	options "EDCrypt/pkg/flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func checkFileExist(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil || os.IsExist(err)
}

func main() {
	opt := options.GetFlag()

	if opt.Encrypt && opt.Output == "" {
		log.Fatal("specify the output flag")
	}

	// check file is exist
	if !checkFileExist(opt.File) {
		log.Fatalf("file %s not exist", opt.File)
	}

	fmt.Print("Password:")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatal(err)
	}

	password := string(bytePassword)

	enc := encryption.Encryption{
		Key:    password,
		Opt: opt,
	}

	if opt.Decrypt {
		text ,err := enc.DecryptFile()
		if err != nil {
			log.Fatal(err)
		}

		if opt.Show {
			fmt.Println(text)
			return
		} else {
			app_pass, err := enc.GetApp(text)
			if err != nil {
				log.Fatal(err)
			}
			if app_pass == "" {
				log.Fatal("app not found")
			}
			if len(strings.Split(app_pass, ":")) == 2 {
				enc.SaveInClipboard(strings.Split(app_pass, ":")[1])
				fmt.Println("Done.")
			} else {
				log.Fatal("App not found")
			}
			
		}
	} else if opt.Encrypt {
		err := enc.EncryptFile()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatal("specify the flag encryption")
	}
}
