package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Binject/forger/pe"
)

func main() {
	//ripSig := flag.Bool("r", false, "Copy signature to from the input file to disk")
	//addSig := flag.Bool("a", false, "Add signature from input file to target file")
	//truncate := flag.Bool("T", false, "Remove signature from input file")
	//checkSig := flag.Bool("c", false, "File to check if signature is present; validity is not checked")
	signedFilePath := flag.String("i", "", "File to copy the signature from")
	//sigFile := flag.String("s", "", "Path to binary signature on disk")
	targetFilePath := flag.String("t", "", "File to be signed")
	outputFilePath := flag.String("o", "", "Output file")
	flag.Parse()

	if (*signedFilePath == "") || (*targetFilePath == "") || (*outputFilePath == "") {
		fmt.Printf("Error: Need values for all flags\n")
		fmt.Printf("i: %v\n", *signedFilePath)
		fmt.Printf("t: %v\n", *targetFilePath)
		fmt.Printf("o: %v\n", *outputFilePath)
	} else {
		signedFileData, err := ioutil.ReadFile(*signedFilePath)
		if err != nil {
			return
		}
		targetFileData, err := ioutil.ReadFile(*targetFilePath)
		if err != nil {
			return
		}
		outputFileData, err := pe.SigRip(signedFileData, targetFileData)
		if err != nil {
			fmt.Printf("Error running SigRip: %v\n", err.Error())
		}
		ioutil.WriteFile(*outputFilePath, outputFileData, os.FileMode(0755))

		fmt.Printf("Worked, output file is at: %v\n", *outputFilePath)
	}

}
