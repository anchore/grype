package tests

import (
	"log"
	"os"
)

func CloseFile(f *os.File) {
	err := f.Close()

	if err != nil {
		log.Fatal("error closing file")
	}
}
