package main

import (
	"context"
	"log"
	"net"

	// tls "github.com/wwhtrbbtt/crypto-tls"

	"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
	// "go.mongodb.org/mongo-driver/bson"
	// "go.mongodb.org/mongo-driver/mongo"
	// "go.mongodb.org/mongo-driver/mongo/options"
)

var Gja3 JA3Calculating
var cert tls.Certificate
var c *Config = &Config{}

var ctx = context.TODO()
// var collection *mongo.Collection

// var client *mongo.Client

func init() {
	err := c.LoadFromFile()
	if err != nil {
		log.Fatal(err)
	}
	// clientOptions := options.Client().ApplyURI(c.MongoURL)
	// client, err = mongo.Connect(ctx, clientOptions)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// err = client.Ping(ctx, nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// collection = client.Database("TrackMe").Collection("requests")

	// _, err = collection.Indexes().CreateOne(
	// 	context.Background(),
	// 	mongo.IndexModel{
	// 		Keys:    bson.D{{Key: "hash", Value: 1}},
	// 		Options: options.Index().SetUnique(true),
	// 	})
	// if err != nil {
	// 	log.Println(err)
	// }

}

func StartRedirectServer(host, port string) {
	log.Println("Starting Redirect Server")
	log.Println("Listening on", host+":"+port)

	ln, err := net.Listen("tcp", host+":"+port)
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()

	for {
		conn, err := ln.Accept()
		log.Println("Redirect: Accepted connection", conn.RemoteAddr())
		if err != nil {
			conn.Close()
			log.Println("Error accepting connection", err)
		}
		go func() {
			conn.Write([]byte("HTTP/1.1 301 Moved Permanently\r\nLocation: https://tls.peet.ws\r\n\r\n"))
			conn.Close()
		}()
	}
}

func main() {
	log.Println("Starting server...")
	log.Println("Listening on " + c.Host + ":" + c.TLSPort)
	log.Println(c.CertFile, c.KeyFile)
	// Load the TLS certificates
	var err error
	cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		log.Fatal("Error loading TLS certificates", err)
	}
	// Create a TLS configuration
	config := tls.Config{
		ServerName: c.Host,
		NextProtos: []string{
			"h2",
		},
		GetCertificate: FingerprintMSG,
	}

	listener, err := tls.Listen("tcp", c.Host+":"+c.TLSPort, &config)
	if err != nil {
		log.Fatal("Error starting tcp listener", err)
	}

	defer listener.Close()
	go StartRedirectServer(c.Host, c.HTTPPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection", err)
		}
		go handleConnection(conn)
	}

}
