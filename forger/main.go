package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/Binject/forger/pe"
)

func main() {
	copySig := flag.Bool("c", false, "Copy signature from input file to target file")
	addSig := flag.Bool("a", false, "Add signature from input cert to target file")
	ripSig := flag.Bool("r", false, "Copy signature to from the input file to disk")
	checkSig := flag.Bool("C", false, "File to check if signature is present; validity is not checked")
	truncate := flag.Bool("T", false, "Remove signature from input file")
	signedFilePath := flag.String("i", "", "File to copy the signature from")
	sigFilePath := flag.String("s", "", "Path to binary signature on disk")
	targetFilePath := flag.String("t", "", "File to be signed")
	outputFilePath := flag.String("o", "", "Output file")
	flag.Parse()

	if *copySig {
		if (*signedFilePath == "") || (*targetFilePath == "") || (*outputFilePath == "") {
			log.Println("Error: '-c' requires '-i', '-t', '-o'")
			return
		}
		signedFileData, err := ioutil.ReadFile(*signedFilePath)
		if err != nil {
			return
		}
		targetFileData, err := ioutil.ReadFile(*targetFilePath)
		if err != nil {
			return
		}
		outputFileData, err := pe.CopySig(signedFileData, targetFileData)
		if err != nil {
			log.Printf("Error running forger: %v\n", err.Error())
			return
		}
		ioutil.WriteFile(*outputFilePath, outputFileData, os.FileMode(0755))

		log.Printf("Worked, output file is at: %v\n", *outputFilePath)
	} else if *addSig {
		if (*sigFilePath == "") || (*targetFilePath == "") || (*outputFilePath == "") {
			log.Println("Error: '-a' requires '-s', '-t', '-o'")
			return
		}
		cert, err := ioutil.ReadFile(*sigFilePath)
		if err != nil {
			return
		}
		targetFileData, err := ioutil.ReadFile(*targetFilePath)
		if err != nil {
			return
		}
		outputFileData, err := pe.WriteCert(targetFileData, cert)
		if err != nil {
			log.Printf("Error running forger: %v\n", err.Error())
			return
		}
		ioutil.WriteFile(*outputFilePath, outputFileData, os.FileMode(0755))

		log.Printf("Worked, output file is at: %v\n", *outputFilePath)
	} else if *ripSig {
		if (*signedFilePath == "") || (*outputFilePath == "") {
			log.Println("Error: '-r' requires '-i', '-o'")
			return
		}
		signedFileData, err := ioutil.ReadFile(*signedFilePath)
		if err != nil {
			return
		}
		cert, err := pe.GetCert(signedFileData)
		if err != nil {
			log.Printf("Error running forger: %v\n", err.Error())
			return
		}
		ioutil.WriteFile(*outputFilePath, cert, os.FileMode(0755))

		log.Printf("Worked, output cert is at: %v\n", *outputFilePath)
	} else if *checkSig {
		if *signedFilePath == "" {
			log.Println("Error: '-C' requires '-i'")
			return
		}
		signedFileData, err := ioutil.ReadFile(*signedFilePath)
		if err != nil {
			return
		}
		containsCert, err := pe.CheckCert(signedFileData)
		if err != nil {
			log.Printf("Error running forger: %v\n", err.Error())
			return
		}
		if containsCert {
			log.Printf("Input file contains a cert")
		} else {
			log.Printf("Input file does not contain a cert")
		}
	} else if *truncate {
		if (*signedFilePath == "") || (*outputFilePath == "") {
			log.Println("Error: '-T' requires '-i', '-o'")
		}
		signedFileData, err := ioutil.ReadFile(*signedFilePath)
		if err != nil {
			return
		}
		outputFileData, err := pe.RemoveCert(signedFileData)
		if err != nil {
			log.Printf("Error running forger: %v\n", err.Error())
			return
		}
		ioutil.WriteFile(*outputFilePath, outputFileData, os.FileMode(0755))

		log.Printf("Worked, output file is at: %v\n", *outputFilePath)
	} else {
		log.Println("Error: no option selected")
		return
	}

}
