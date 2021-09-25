package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	// "strconv"

	"github.com/Danny-Dasilva/Ja3-Http2/crypto/tls"
	"github.com/Danny-Dasilva/Ja3-Http2/net/http"
)


func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	// log.Println(r)
	// log.Println(r.JA3Fingerprint)
	// hash := md5.Sum([]byte(r.JA3Fingerprint))
	// log.Println(hash)
	log.Println(r)
	// log.Println(r.JA3Fingerprint)
	// hash := md5.Sum([]byte(r.JA3Fingerprint))
	// log.Println(hash)

	// out := make([]byte, 32)
	// hex.Encode(out, hash[:])
	// 	// Prevent results from being registered twice
	// 	w.Header().Set("Cache-Control", "public,max-age=31556926,immutable")
	// 	w.Header().Set("Expires", "Mon, 30 Dec 2019 08:00:00 GMT")
	// 	w.Header().Set("Last-Modified", "Sun, 30 Dec 2018 08:00:00 GMT")
	// 	w.WriteHeader(200)
	// 	w.Write(out)

	// 	_, err := client.HIncrBy("freqs", string(out), 1).Result()
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}
	// 	_, err = client.HIncrBy("freqs", "total", 1).Result()
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}
	// } else {
	
		// numF, err := strconv.ParseFloat(string(out), 64)
		// if err != nil {
		// 	fmt.Println(err)
		// 	w.WriteHeader(200)
		// 	w.Write([]byte("error"))
		// 	return
		// }
	
	// }
}

func main() {
	

	

	handler := http.HandlerFunc(handler)
	server := &http.Server{Addr: ":8443", Handler: handler}

	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	cert, err := tls.LoadX509KeyPair("testdata/example-cert.pem", "testdata/example-key.pem")
	if err != nil {
		panic(err)
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}

	tlsListener := tls.NewListener(ln, &tlsConfig)
	fmt.Println("HTTP up.")
	err = server.Serve(tlsListener)
	if err != nil {
		panic(err)
	}

	ln.Close()
}