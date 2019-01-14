package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
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

	peHeaderLoc := uint32(binary.LittleEndian.Uint32(peData[0x3c:]))
	peHeaderLoc += 4

	var certTableDataLoc uint32
	var certTableOffset uint32
	var certTableSize uint32

	arch := peFile.FileHeader.Machine
	if arch == 0x14c {
		optionalHeader := peFile.OptionalHeader.(*pe.OptionalHeader32)
		certTableDataLoc = peHeaderLoc + 20 + 128
		certTableOffset = optionalHeader.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = optionalHeader.DataDirectory[CERTIFICATE_TABLE].Size
	} else if arch == 0x8664 {
		optionalHeader := peFile.OptionalHeader.(*pe.OptionalHeader64)
		certTableDataLoc = peHeaderLoc + 20 + 144
		certTableOffset = optionalHeader.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = optionalHeader.DataDirectory[CERTIFICATE_TABLE].Size
	} else {
		return 0, 0, 0, errors.New("architecture not supported")
	}

	return int64(certTableDataLoc), int64(certTableOffset), int64(certTableSize), nil
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
