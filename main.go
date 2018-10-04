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
	"crypto/rsa"
    "crypto/sha1"
    "encoding/pem"
    "encoding/json"
    "encoding/binary"
)

func main() {
	fmt.Printf("hello, world\n")

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
		&path, "path", "./", 
		"Path")

	flag.Parse()

	switch mode {
	case "z": 
		szip(path, cert, pkey)
	case "x":
		extract()
	case "i":
		info()
	default:
		fmt.Printf("Enter mode\n")
	}

}

func szip (path string, cert string, pkey string) {
	//Create buffer and writer for zip archive
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	//Create buffer and writer for metadata
	metaBuf := new(bytes.Buffer)
	metaBuf.WriteString("files: [ \n")

	//Zip files
	ZipFileWriter(path, filepath.Base(path) + "/", zipWriter, metaBuf)

	//Add closing brackets to metadata
	metaBuf.WriteString("]")

	//Create metadata file
	metaFile, err := os.Create("meta.json")
	if err != nil {
	    log.Fatal(err)
	}
	metaFile.Write(metaBuf.Bytes())
	metaFile.Close()	

	//Create COMPRESSED metadata 
	zipMetaBuf := new(bytes.Buffer)
	zipMetaWriter := zip.NewWriter(zipMetaBuf)
	m, err := zipMetaWriter.Create("meta.json")
	if err != nil {
		log.Fatal(err)
	}
	m.Write(metaBuf.Bytes())
	err = zipMetaWriter.Close()
	if err != nil {
		log.Fatal(err)
	}

	zipMetaFile, err := os.Create("compressed_meta.zip")
	if err != nil {
	    log.Fatal(err)
	}
	zipMetaFile.Write(zipMetaBuf.Bytes())
	zipMetaFile.Close()

	// Closing zip writer and creating .zip file
	err = zipWriter.Close()
	if err != nil {
		log.Fatal(err)
	}

	zipFile, err := os.Create(filepath.Base(path) + ".zip")
	if err != nil {
	    log.Fatal(err)
	}
	zipFile.Write(zipBuf.Bytes())
	zipFile.Close()

	//Creating .szp file
	metaSize := new(bytes.Buffer)
	err = binary.Write(metaSize, binary.BigEndian, uint32(binary.Size(metaBuf.Bytes())))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(binary.BigEndian.Uint32(metaSize.Bytes()))
	stufToSign := append(metaSize.Bytes(), zipMetaBuf.Bytes()...)
	stufToSign = append(stufToSign, zipBuf.Bytes()...)
	SignArchive(stufToSign, filepath.Base(path) + ".szp", cert, pkey)
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

func ZipFileWriter(path string, pathTrace string, zipWriter *zip.Writer, metaBuf *bytes.Buffer) {

    //Get all files from desired path
	filesToWrite, err := ioutil.ReadDir(path)
    if err != nil {
        log.Fatal(err)
    }

	//Create folder in current directory for unzip
    zipWriter.Create(pathTrace)

	//Search all files inside this destination
	for _, file := range filesToWrite {
		if file.IsDir(){
			ZipFileWriter(path + "/" + file.Name(), pathTrace + file.Name() + "/", zipWriter, metaBuf)
		} else {
			f, err := zipWriter.Create(pathTrace + file.Name())
			if err != nil {
	            log.Fatal(err)
	        }

	        fileBody, err := ioutil.ReadFile(path + "/" + file.Name())
	        _, err = f.Write(fileBody)
	        if err != nil {
	            log.Fatal(err)
	        }

	        fileHeader, err := zip.FileInfoHeader(file)
	        if err != nil {
	            log.Fatal(err)
	        }
	        meta := FileToMeta(fileHeader, fileBody)

	        jsonMeta, err := json.Marshal(&meta)
	        if err != nil {
	            log.Fatal(err)
	        }

	        metaBuf.WriteString(string(jsonMeta))
	        metaBuf.WriteString(", \n")
		}
		
	}
}

func SignArchive(stufToSign []byte, name string, cert string, pkey string){
	//Create data to sign
	signedData, err := pkcs7.NewSignedData(stufToSign)
	if err != nil {
	    fmt.Printf("Cannot initialize signed data: %s", err)
	}

	//Load certificate
	certFile, err := ioutil.ReadFile(cert)
	if err != nil {
		log.Fatal(err)
	}
	certBlock, _ := pem.Decode(certFile)
	if certBlock == nil {
		panic("failed to parse certificate PEM")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	//Load private key
	pkeyFile, err := ioutil.ReadFile(pkey)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(pkeyFile)
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	var privateKey *rsa.PrivateKey
	privateKey = parseResult.(*rsa.PrivateKey)
	if err != nil {
		fmt.Println("!!")
		log.Fatal(err)
	}


	//Sign data
	signedData.AddSigner(certificate, privateKey, pkcs7.SignerInfoConfig{}) 
	if err != nil {
	    log.Fatal("Cannot add signer: %s", err)
	}

	szip, err := signedData.Finish()
	if err != nil {
	    log.Fatal("Cannot finish signing data: %s", err)
	}

	szpFile, err := os.Create(name)
	if err != nil {
	    log.Fatal(err)
	}
	szpFile.Write(szip)

	szpFile.Close()
}