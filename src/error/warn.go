package error

import (
	"log"
)

func Warn(err error) {
	if err != nil {
		log.Println(err)
	}
}
