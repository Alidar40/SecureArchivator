package main

import 
(	
	"fmt"
	"flag"
	"archive/zip"
	"bytes"
	"log"
	"os"
	"io/ioutil"
	"path/filepath"
	pkcs7 "github.com/fullsailor/pkcs7"
	"crypto/x509"
	"crypto/tls"
    "crypto/sha1"
    "encoding/json"
    "encoding/binary"
)

func main() {
	fmt.Printf("Processing...\n")

	var mode, hash, cert, pkey, path string

	flag.StringVar(
		&mode, "mode", "i", 
		"Mode: z, x or i")
	
	flag.StringVar(
		&hash, "hash", "", 
		"Hash")

	flag.StringVar(
		&cert, "cert", "./my.crt", 
		"Cert")

	flag.StringVar(
		&pkey, "pkey", "./my.key", 
		"Pkey")

	flag.StringVar(
		&path, "path", "./packme", 
		"Path")

	flag.Parse()

	switch mode {
	case "z": 
		err := szip(path, cert, pkey)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		fmt.Printf("Packed successfully!\n")
		os.Exit(0)
	case "x":
		extract()
	case "i":
		info()
	default:
		fmt.Printf("Enter mode\n")
		os.Exit(-1)
	}

}

func szip (path string, cert string, pkey string) error {
	//Create buffer and writer for zip archive
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	//Create buffer for metadata
	var meta []FileMeta

	//Zip files
	err := ZipFileWriter(path, filepath.Base(path) + "/", zipWriter, &meta)
	if err != nil {
		return err
	}

	//Closing zip writer 
	//If defer was used, loss of data would occur
	err = zipWriter.Close()
	if err != nil {
		log.Fatal(err)
	}

	//Obtaining meta
    jsonMeta, err := json.Marshal(&meta)
    if err != nil {
        return err
    }

	//Create compressed metadata 
	zipMetaBuf := new(bytes.Buffer)
	zipMetaWriter := zip.NewWriter(zipMetaBuf)
	m, err := zipMetaWriter.Create("meta.json")
	if err != nil {
		return err
	}

	_, err = m.Write(jsonMeta)
	if err != nil {
		return err
	}

	//Closing zip writer for metadata
	//If defer was used, loss of data would occur
	err = zipMetaWriter.Close()
	if err != nil {
		return err
	}

	//Creating .szp file
	metaSize := new(bytes.Buffer)
	err = binary.Write(metaSize, binary.BigEndian, uint32(binary.Size(jsonMeta)))
	if err != nil {
		log.Fatal(err)
	}

	stufToSign := append(metaSize.Bytes(), zipMetaBuf.Bytes()...)
	stufToSign = append(stufToSign, zipBuf.Bytes()...)

	err = SignArchive(stufToSign, filepath.Base(path) + ".szp", cert, pkey)
	if err != nil {
		return err
	}

	return nil
}

func extract() {

}

func info(){

}

type FileMeta struct {
	Name string `json:"name"`
	OriginalSize uint64 `json:"original_size"`
	CompressedSize uint64 `json:"compressed_size"`
	ModTime string `json:"mod_time"`
	Sha1Hash [20]byte `json:"sha1_hash"`
}

func FileToMeta(header *zip.FileHeader, fileBody []byte) (FileMeta){
	fileMeta := FileMeta{
		Name: header.Name,
		OriginalSize: header.UncompressedSize64,
		CompressedSize: header.CompressedSize64,
		ModTime: header.Modified.Format("Monday, 02-Jan-06 15:04:05 MST"),
		Sha1Hash: sha1.Sum(fileBody),
	}

	return fileMeta
}

func ZipFileWriter(path string, pathTrace string, zipWriter *zip.Writer, meta *[]FileMeta) error {

    //Get all files from desired path
	filesToWrite, err := ioutil.ReadDir(path)
    if err != nil {
        return err
    }

	//Create folder in current directory for unzip
    zipWriter.Create(pathTrace)

	//Search all files inside this destination
	for _, file := range filesToWrite {
		if file.IsDir(){
			ZipFileWriter(path + "/" + file.Name(), pathTrace + file.Name() + "/", zipWriter, meta)
		} else {
			f, err := zipWriter.Create(pathTrace + file.Name())
			if err != nil {
	            return err
	        }

	        fileBody, err := ioutil.ReadFile(path + "/" + file.Name())
	        _, err = f.Write(fileBody)
	        if err != nil {
	            return err
	        }

	        fileHeader, err := zip.FileInfoHeader(file)
	        if err != nil {
	            return err
	        }

	        *meta = append(*meta, FileToMeta(fileHeader, fileBody))
		}
		
	}

	return nil
}

func SignArchive(stufToSign []byte, name string, cert string, pkey string) error {
	//Create data to sign
	signedData, err := pkcs7.NewSignedData(stufToSign)
	if err != nil {
	    return err
	}

	//Parse certificate file
	certificate, err := tls.LoadX509KeyPair(cert, pkey)
	if err != nil {
		return err
	}

	//Obtain the necessary key
	rsaPKey := certificate.PrivateKey
	rsaCert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return err
	}

	//Sign data
	signedData.AddSigner(rsaCert, rsaPKey, pkcs7.SignerInfoConfig{}) 
	if err != nil {
	    return err
	}

	//Obtain final bytes
	szip, err := signedData.Finish()
	if err != nil {
	    return err
	}

	//Write them to file
	szpFile, err := os.Create(name)
	if err != nil {
	    return err
	}
	defer szpFile.Close()
	
	_, err = szpFile.Write(szip)
	if err != nil {
		return err
	}
	
	return nil
}