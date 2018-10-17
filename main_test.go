package main

import (
	"io/ioutil"
	"bytes"
	"testing"
)

func TestZip (t *testing.T){
	err := szip("./test/perfect_unzipped", "./test/imprecise", "./my.crt", "./my.key")
	if err != nil {
		t.Error(err)
	}

	test_zipped, err := ioutil.ReadFile("./test/imprecise/perfect_unzipped.szp")
	if err != nil {
		t.Error(err)
	}

	perfect_zipped, err := ioutil.ReadFile("./test/perfect_zipped.szp")
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(test_zipped[10:15], perfect_zipped[10:15]) != 0 {
		t.Errorf("zip is incorrect")
	}
}

func TestExtract(t *testing.T){
	err := extract("./test/imprecise/perfect_unzipped.szp", "./test/imprecise/", "./my.crt", "./my.key", "UNDEF")
	if err != nil {
		t.Error(err)
	}

	perfectFiles, err := ioutil.ReadDir("./test/perfect_unzipped")
    if err != nil {
        t.Error(err)
    }

    unzippedFiles, err := ioutil.ReadDir("./test/imprecise/perfect_unzipped")
    if err != nil {
        t.Error(err)
    }

    if len(perfectFiles) != len(unzippedFiles){
    	t.Error("Unzipped files don't match perfect files")
    }

    for i := 0; i < len(perfectFiles); i += 1 {
    	if perfectFiles[i].Name() != unzippedFiles[i].Name(){
    		t.Error("Unzipped files names don't match perfect files names")
    	}

    	if perfectFiles[i].Size() != unzippedFiles[i].Size(){
    		t.Error("Unzipped files sizes don't match perfect files sizes")
    	}
    }
}