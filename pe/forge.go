package pe

import (
	"bytes"
	"errors"

	"github.com/Binject/debug/pe"
)

// CERTIFICATE_TABLE is the index of the Certificate Table info in the Data Directory structure
// in the PE header
const CERTIFICATE_TABLE = 4

var errNoCert = errors.New("input file is not signed")

// CopySig takes byte slices of a signed PE file, a PE file to sign, and returns a new byte slice
// of a PE file by taking the signature from the first file and adding it to the second file
func CopySig(signedFileData, targetFileData []byte) ([]byte, error) {
	signedFileReader := bytes.NewReader(signedFileData)
	signedPEFile, err := pe.NewFile(signedFileReader)
	if err != nil {
		return nil, err
	}

	targetFileReader := bytes.NewReader(targetFileData)
	targetPEFile, err := pe.NewFile(targetFileReader)
	if err != nil {
		return nil, err
	}

	targetPEFile.CertificateTable = signedPEFile.CertificateTable
	outputPEData, err := targetPEFile.Bytes()
	if err != nil {
		return nil, err
	}

	return outputPEData, nil
}

func GetCert(peData []byte) ([]byte, error) {
	targetFileReader := bytes.NewReader(peData)
	targetPEFile, err := pe.NewFile(targetFileReader)
	if err != nil {
		return nil, err
	}

	cert := targetPEFile.CertificateTable
	if cert == nil {
		return nil, errNoCert
	}

	return cert, nil
}

func WriteCert(peData, cert []byte) ([]byte, error) {
	targetFileReader := bytes.NewReader(peData)
	targetPEFile, err := pe.NewFile(targetFileReader)
	if err != nil {
		return nil, err
	}

	targetPEFile.CertificateTable = cert
	outputPEData, err := targetPEFile.Bytes()
	if err != nil {
		return nil, err
	}

	return outputPEData, nil
}

// RemoveCert returns a byte slice of a PE file without it's cert if it has one
func RemoveCert(peData []byte) ([]byte, error) {
	targetFileReader := bytes.NewReader(peData)
	targetPEFile, err := pe.NewFile(targetFileReader)
	if err != nil {
		return nil, err
	}

	if targetPEFile.CertificateTable == nil {
		return nil, errNoCert
	}

	targetPEFile.CertificateTable = nil
	outputPEData, err := targetPEFile.Bytes()
	if err != nil {
		return nil, err
	}

	return outputPEData, nil
}

// CheckCert returns true if input byte slice of a PE file contains an embedded cert
func CheckCert(peData []byte) (bool, error) {
	targetFileReader := bytes.NewReader(peData)
	targetPEFile, err := pe.NewFile(targetFileReader)
	if err != nil {
		return false, err
	}

	if targetPEFile.CertificateTable == nil {
		return false, nil
	}

	return true, nil
}
