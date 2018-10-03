package main

import 
(	
	"fmt"
	"flag"
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
		szip()
	case "x":
		extract()
	case "i":
		info()
	default:
		fmt.Printf("Enter mode\n")
	}

}

func szip () {

}

func extract() {

}

func info(){

}