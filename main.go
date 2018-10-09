package main

import 
(	
	"fmt"
	"flag"
	"archive/zip"
	"bytes"
	"os"
	"errors"
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
	var mode, hash, cert, pkey, source, destination string

	flag.StringVar(
		&mode, "mode", "i", 
		"Modes: z(zip), x(extract) or i(info)")
	
	flag.StringVar(
		&hash, "hash", "UNDEF", 
		"Hash")

	flag.StringVar(
		&cert, "cert", "./my.crt", 
		"Cert")

	flag.StringVar(
		&pkey, "pkey", "./my.key", 
		"Pkey")

	flag.StringVar(
		&source, "s", "UNDEF", 
		"Source")

	flag.StringVar(
		&destination, "d", "./", 
		"Destination")

	flag.Parse()

	switch mode {
	case "z": 
		fmt.Printf("Processing...\n")
		if source == "UNDEF" {
			fmt.Println("Source undefined!")
			os.Exit(-1)
		}

		err := szip(source, destination, cert, pkey)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		fmt.Printf("Packed successfully!\n")
		os.Exit(0)

	case "x":
		fmt.Printf("Processing...\n")
		if source == "UNDEF" {
			fmt.Println("Source undefined!")
			os.Exit(-1)
		}

		err := extract(source, destination, cert, pkey, hash)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		fmt.Printf("Unpacked successfully!\n")
		os.Exit(0)

	case "i":
		info()
		os.Exit(0)

	default:
		fmt.Println("Using -mode flag is mandatory!")
		fmt.Println("-mode falg accepts only 3 values: z (zip), x(extract) and i(info).")
		fmt.Println("For more information use -mode=i")
		os.Exit(-1)
	}

}

func szip (source string, destination string, cert string, pkey string) error {
	//Create buffer and writer for zip archive
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	//Create buffer for metadata
	var meta []FileMeta

	//Zip files
	err := ZipFileWriter(source, filepath.Base(source) + "/", zipWriter, &meta)
	if err != nil {
		return err
	}

	//Closing zip writer 
	//If defer was used, loss of data would occur
	err = zipWriter.Close()
	if err != nil {
		return err
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
	err = binary.Write(metaSize, binary.BigEndian, uint32(binary.Size(zipMetaBuf.Bytes())))
	if err != nil {
		return err
	}

	stufToSign := append(metaSize.Bytes(), zipMetaBuf.Bytes()...)
	stufToSign = append(stufToSign, zipBuf.Bytes()...)

	err = SignArchive(stufToSign, destination, filepath.Base(source) + ".szp", cert, pkey)
	if err != nil {
		return err
	}

	return nil
}

func extract(source string, destination string, cert string, pkey string, hash string) error {
	//Reading .szp file
	szp, err := ioutil.ReadFile(source)
	if err != nil {
		return err
	}

	sign, err := pkcs7.Parse(szp)
	if err != nil {
		return err
	}

	//Verifying certificate
	err = sign.Verify()
	if err != nil {
		return err
	}

	signer := sign.GetOnlySigner()
	if signer == nil {
		return errors.New("ERROR: There are more or less than one signer")
	}

	if hash != "UNDEF" {
		if hash != fmt.Sprintf("%x", sha1.Sum(signer.Raw)) {
			fmt.Println(fmt.Sprintf("%x", sha1.Sum(signer.Raw)))
			return errors.New("ERROR: Certificate hash is corrupted")
		}
	}

	//Parse certificate file
	certificate, err := tls.LoadX509KeyPair(cert, pkey)
	if err != nil {
		return err
	}

	//Obtain the necessary key
	rsaCert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return err
	}

	if bytes.Compare(rsaCert.Raw, signer.Raw) != 0 {
		return errors.New("ERROR: Certificates don't match")
	}

	//Read meta
	metaSize := int64(binary.BigEndian.Uint32(sign.Content[:4]))
	bytedMeta := bytes.NewReader(sign.Content[4:metaSize+4])

	readableMeta, err := zip.NewReader(bytedMeta, bytedMeta.Size())
	if err != nil {
		return err
	}

	metaCompressed := readableMeta.File[0] //meta.json

	metaUncompressed, err := metaCompressed.Open()
	if err != nil {
		return err
	}
	defer metaUncompressed.Close()

	var fileMetas []FileMeta
	metaUncompressedBody, err := ioutil.ReadAll(metaUncompressed)
	if err != nil {
		return err
	}
	err = json.Unmarshal(metaUncompressedBody, &fileMetas)
	if err != nil {
		return err
	}
	//fileMetas - our ready to go .json metas

	//Read archive
	bytedArchive := bytes.NewReader(sign.Content[4+metaSize:])

	zipReader, err := zip.NewReader(bytedArchive, bytedArchive.Size()) 
	if err != nil {
		return err
	}

	err = ZipFileReader(zipReader, fileMetas, destination)
	if err != nil {
		return err
	}
	return nil
}

func info(){
	fmt.Println("Welcome to Secure Archivator!\n")
	fmt.Println("You can use these flags:")
	fmt.Println("	-mode - accepts only 3 values: z (zip), x(extract) and i(info). Using this flag is mandatory.\n")
	fmt.Println("	-s - source - path either to folder to pack (if -mode=z) or to archive to unpack (if -mode=x). In the last case path should end with \".szp\". By default is undefined and you must point it explicitly.\n")
	fmt.Println("	-d - destination - path euther to folder where to save the .szp archive (if -mode=z) or to folder where to unpack (if -mode=x). By default is \"./\".\n")
	fmt.Println("	-cert - path to .crt certificate. By default is %userprofile%/my.crt\n")
	fmt.Println("	-pkey - path to .key private key. By default is %userprofile%/my.key\n")
	fmt.Println("	-hash - certificate's hash. Is used to verify signature when unpacking archive.\n")
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

func ZipFileWriter(source string, pathTrace string, zipWriter *zip.Writer, meta *[]FileMeta) error {

    //Get all files from desired source
	filesToWrite, err := ioutil.ReadDir(source)
    if err != nil {
        return err
    }

	//Create folder in current directory for unzip
    zipWriter.Create(pathTrace)

	//Search all files inside this destination
	for _, file := range filesToWrite {
		if file.IsDir(){
			ZipFileWriter(source + "/" + file.Name(), pathTrace + file.Name() + "/", zipWriter, meta)
		} else {
			f, err := zipWriter.Create(pathTrace + file.Name())
			if err != nil {
	            return err
	        }

	        fileBody, err := ioutil.ReadFile(filepath.Join(source, file.Name()))
	        if err != nil {
	            return err
	        }

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

func ZipFileReader(zipReader *zip.Reader, fileMetas []FileMeta, destination string) error{
	for _, file := range zipReader.File {
		fileContent, err := file.Open()
		if err != nil {
			return err
		}

		fileBody, err := ioutil.ReadAll(fileContent)
		if err != nil {
			return err
		}

		for _, meta := range fileMetas{
			if meta.Name == filepath.Base(file.Name) {
				fileHash := sha1.Sum(fileBody)
				if meta.Sha1Hash != fileHash {
					return errors.New("ERROR: Got damaged hash of file " + file.Name)
				}
			}
		}

		fileInfo := file.FileInfo()
		if fileInfo.IsDir() {
			_, err := os.Stat(filepath.Join(destination, filepath.Base(file.Name))) 
			if os.IsNotExist(err) {
			    os.MkdirAll(filepath.Join(destination, file.Name), os.ModePerm)
			} else {
				return errors.New("ERROR: Folder " + file.Name + " already exists")
			}
		} else {
			f, err := os.Create(filepath.Join(destination, file.Name))
			if err != nil {
				return err
			}
			
			_, err = f.Write(fileBody)
			if err != nil {
				return err
			}
		}

		fileContent.Close()
	}

	return nil
}

func SignArchive(stufToSign []byte, destination string, name string, cert string, pkey string) error {
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
	err = signedData.AddSigner(rsaCert, rsaPKey, pkcs7.SignerInfoConfig{}) 
	if err != nil {
	    return err
	}

	//Obtain final bytes
	szip, err := signedData.Finish()
	if err != nil {
	    return err
	}

	//Output the certificate
	fmt.Printf("Certificate's hash: %x\n", sha1.Sum(rsaCert.Raw))

	//Write them to file
	szpFile, err := os.Create(filepath.Join(destination, name))
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