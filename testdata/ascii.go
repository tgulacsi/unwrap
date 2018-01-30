package main

import "fmt"
import "os"

func main() {
	fmt.Print(`CREATE OR REPLACE
PROCEDURE x_ascii IS
BEGIN
  x := '`)
	for i := byte(0); i < 255; i++ {
		os.Stdout.Write([]byte{i})
		if i == '\'' {
			os.Stdout.Write([]byte{i})
		}
	}
	fmt.Print(`';
END;
/
`)
}
