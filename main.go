package main

import (
	"bytes"
	"debug/pe"
	"flag"
	"fmt"
	"encoding/binary"
	"io"
	"os"
)

const CERTIFICATE_TABLE = 4

func main() {
	signedFilePath := flag.String("i", "", "File to copy the signature from")
	targetFilePath := flag.String("t", "", "File to be signed")
	outputFilePath := flag.String("o", "", "File that will be written to")
	flag.Parse()

	signedFile, err := os.Open(*signedFilePath)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	defer signedFile.Close()

	_, certTableOffset, certTableSize, err := GetCertTableInfo(signedFile)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	if certTableOffset == 0 || certTableSize == 0 {
		fmt.Println("Input file is not signed!")
		return
	}

	// grab the cert
	cert := make([]byte, certTableSize)
	certTableSR := io.NewSectionReader(signedFile, certTableOffset, certTableSize)
	certTableSR.Seek(0, io.SeekStart)
	binary.Read(certTableSR, binary.LittleEndian, &cert)

	targetFile, err := os.Open(*targetFilePath)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	defer targetFile.Close()

	certTableLoc, _, _, err := GetCertTableInfo(targetFile)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	outputFile, err := os.OpenFile(*outputFilePath, os.O_RDWR|os.O_TRUNC, os.FileMode(0755))
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	defer outputFile.Close()
	fileSize, err := io.Copy(outputFile, targetFile)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	// seek to Certificate Table entry of Data Directories
	outputFile.Seek(certTableLoc, 0)
	// write the start of the new Certificate Table
	binary.Write(outputFile, binary.LittleEndian, Int64ToBytes(fileSize))
	// write the size of the Certificate Table
	binary.Write(outputFile, binary.LittleEndian, Int64ToBytes(int64(len(cert))))
	outputFile.Seek(0, 2)
	// append the cert(s)
	binary.Write(outputFile, binary.LittleEndian, cert)
}

func GetCertTableInfo(file *os.File) (int64, int64, int64, error) {
	peFile, err := pe.NewFile(file)
	if err != nil {
		return 0, 0, 0, err
	}

	// make sure PR is valid
	var dosheader [96]byte
	var sign [4]byte
	file.ReadAt(dosheader[0:], 0)
	var base int64
	if dosheader[0] == 'M' && dosheader[1] == 'Z' {
		signoff := int64(binary.LittleEndian.Uint32(dosheader[0x3c:]))
		file.ReadAt(sign[:], signoff)
		if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) {
			fmt.Printf("Invalid PE File Format.\n")
		}
		base = signoff + 4
	} else {
		base = int64(0)
	}

	// read the PE header
	headerSR := io.NewSectionReader(file, 0, 1<<63-1)
	headerSR.Seek(base, io.SeekStart)
	binary.Read(headerSR, binary.LittleEndian, &peFile.FileHeader)

	var sizeofOptionalHeader32 = uint16(binary.Size(pe.OptionalHeader32{}))
	var sizeofOptionalHeader64 = uint16(binary.Size(pe.OptionalHeader64{}))

	var oh32 pe.OptionalHeader32
	var oh64 pe.OptionalHeader64
	var certTableDataLoc int64
	var certTableOffset uint32
	var certTableSize uint32

	// find Certificate Table offset and size based off input PE arch
	switch peFile.FileHeader.SizeOfOptionalHeader {
	case sizeofOptionalHeader32:
		err := binary.Read(headerSR, binary.LittleEndian, &oh32)
		if err != nil {
			return 0, 0, 0, err
		}
		if oh32.Magic != 0x10b { // PE32
			fmt.Printf("pe32 optional header has unexpected Magic of 0x%x", oh32.Magic)
		}

		certTableDataLoc = 128
		certTableOffset = oh32.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = oh32.DataDirectory[CERTIFICATE_TABLE].Size

	case sizeofOptionalHeader64:
		err := binary.Read(headerSR, binary.LittleEndian, &oh64)
		if err != nil {
			return 0, 0, 0, err
		}
		if oh64.Magic != 0x20b { // PE32+
			fmt.Printf("pe32+ optional header has unexpected Magic of 0x%x", oh64.Magic)
		}

		certTableDataLoc = 144
		certTableOffset = oh64.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = oh64.DataDirectory[CERTIFICATE_TABLE].Size
	}

	return certTableDataLoc, int64(certTableOffset), int64(certTableSize), nil
}

func Int64ToBytes(n int64) []byte {
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, n)
	return buf.Bytes()[:4]
}
