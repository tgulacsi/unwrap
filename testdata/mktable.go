// build never
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	var start int
	for i := 10; i < len(b); i++ {
		var mismatch bool
		for j := i - 9; j < i; j++ {
			mismatch = mismatch || b[j] != b[i]
		}
		if !mismatch {
			start = i + 1
			break
		}
	}
	if start == 0 {
		log.Fatal("not found 10 consecutive same bytes")
		return
	}
	var a [256]byte
	for j := range a[:] {
		if j == 39 {
			start++ // double ''
		}
		a[b[start+j]] = byte(j)
	}
	fmt.Println("package main\nfunc init() { charMap = [...]byte{")
	for _, c := range a[:] {
		fmt.Println("\t", c, ",")
	}
	fmt.Println("}}")
}
