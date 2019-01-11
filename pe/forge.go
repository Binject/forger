package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"log"
	"io"
)

// CERTIFICATE_TABLE is the index of the Certificate Table info in the Data Directory structure
// in the PE header
const CERTIFICATE_TABLE = 4

// CopySig takes byte slices of a signed PE file, a PE file to sign, and returns a new byte slice
// of a PE file by taking the signature from the first file and adding it to the second file
func CopySig(signedFileData, targetFileData []byte) ([]byte, error) {
	cert, err := GetCert(signedFileData)
	if err != nil {
		return nil, err
	}

	outputFileData, err := WriteCert(targetFileData, cert)
	if err != nil {
		return nil, err
	}

	return outputFileData, nil
}

// GetCert returns the embedded cert from the input byte slice of a PE file
func GetCert(peData []byte) ([]byte, error) {
	_, certTableOffset, certTableSize, err := GetCertTableInfo(peData)
	if err != nil {
		return nil, err
	}
	if certTableOffset == 0 || certTableSize == 0 {
		return nil, errors.New("input file is not signed")
	}

	// grab the cert
	cert := make([]byte, certTableSize)
	cert = peData[certTableOffset:certTableOffset + certTableSize]

	return cert, nil
}

// GetCertTableInfo takes a byte slice of a PE file and returns the Certificate Table location,
// offset, and length
func GetCertTableInfo(peData []byte) (int64, int64, int64, error) {
	peDataReader := bytes.NewReader(peData)
	peFile, err := pe.NewFile(peDataReader)
	if err != nil {
		return 0, 0, 0, err
	}

	// validate PE and grab offset of PE header
	var dosheader [96]byte
	var sign [4]byte
	peDataReader.ReadAt(dosheader[0:], 0)
	var base int64
	if dosheader[0] == 'M' && dosheader[1] == 'Z' {
		signoff := int64(binary.LittleEndian.Uint32(dosheader[0x3c:]))
		peDataReader.ReadAt(sign[:], signoff)
		if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) {
			log.Printf("Invalid PE File Format.\n")
		}
		base = signoff + 4
	} else {
		base = int64(0)
	}

	// read the PE header
	headerSR := io.NewSectionReader(peDataReader, 0, 1<<63-1)
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
			log.Printf("pe32 optional header has unexpected Magic of 0x%x", oh32.Magic)
		}

		certTableDataLoc = base + 20 + 128
		certTableOffset = oh32.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = oh32.DataDirectory[CERTIFICATE_TABLE].Size

	case sizeofOptionalHeader64:
		err := binary.Read(headerSR, binary.LittleEndian, &oh64)
		if err != nil {
			return 0, 0, 0, err
		}
		if oh64.Magic != 0x20b { // PE32+
			log.Printf("pe32+ optional header has unexpected Magic of 0x%x", oh64.Magic)
		}

		certTableDataLoc = base + 20 + 144
		certTableOffset = oh64.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = oh64.DataDirectory[CERTIFICATE_TABLE].Size
	}

	return certTableDataLoc, int64(certTableOffset), int64(certTableSize), nil
}

// WriteCert takes a byte slice of a PE file and a cert, and returns a byte slice of a PE file
// signed with the input cert
func WriteCert(peData, cert []byte) ([]byte, error) {
	certTableLoc, _, _, err := GetCertTableInfo(peData)
	if err != nil {
		return nil,  err
	}

	certTableInfo := &pe.DataDirectory{
		VirtualAddress: uint32(len(peData)),
		Size:           uint32(len(cert)),
	}

	// write the offset and size of the new Certificate Table
	var certTableInfoBuf bytes.Buffer
	binary.Write(&certTableInfoBuf, binary.LittleEndian, certTableInfo)
	peData = append(peData[:certTableLoc], append(certTableInfoBuf.Bytes(), peData[int(certTableLoc) + binary.Size(certTableInfo):]...)...)
	// append the cert(s)
	peData = append(peData, cert...)

	return peData, nil
}

// RemoveCert returns a byte slice of a PE file without it's cert if it has one
func RemoveCert(peData []byte) ([]byte, error) {
	certTableLoc, certTableOffset, certTableSize, err := GetCertTableInfo(peData)
	if err != nil {
		return nil, err
	}
	if certTableOffset == 0 || certTableSize == 0 {
		return nil, errors.New("input file is not signed")
	}

	certTableInfo := &pe.DataDirectory{
		VirtualAddress: uint32(0),
		Size:           uint32(0),
	}

	// chage the offset and size of the Certificate Table to zero
	var certTableInfoBuf bytes.Buffer
	binary.Write(&certTableInfoBuf, binary.LittleEndian, certTableInfo)
	peData = append(peData[:certTableLoc], append(certTableInfoBuf.Bytes(), peData[int(certTableLoc) + binary.Size(certTableInfo):]...)...)
	// remove the cert(s)
	peData = peData[:certTableOffset]

	return peData, nil
}

// CheckCert returns true if input byte slice of a PE file contains an embedded cert
func CheckCert(peData []byte) (bool, error) {
	_, certTableOffset, certTableSize, err := GetCertTableInfo(peData)
	if err != nil {
		return false, err
	}
	if certTableOffset == 0 || certTableSize == 0 {
		return false, nil
	}

	return true, nil
}
