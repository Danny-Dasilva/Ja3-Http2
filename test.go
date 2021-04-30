package main

import (
	// "bytes"
	// "encoding/json"
	"fmt"
	"io/ioutil"
	// "net/url"
	// "path"
	"./ja3transport"
)

// JA3Response is the struct
type JA3Response struct {
	JA3Hash   string `json:"ja3_hash"`
	JA3       string `json:"ja3"`
	UserAgent string `json:"User-Agent"`
}

func main() {

	httpClient,err := ja3transport.NewWithString("771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0")
	if err != nil{
		fmt.Println(err)
		panic(err)
	}

	/* First fetch the JA3 Fingerprint */
	resp, err := httpClient.Get("https://ja3er.com/json")
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	// // unmarshal the response
	// var ja3Response JA3Response
	// err = json.Unmarshal(body, &ja3Response)
	// if err != nil {
	// 	fmt.Println(err)
	// 	panic(err)
	// }
	fmt.Println(string(body))
	// /* Fetch information about the ja3hash*/
	// searchURL, _ := url.Parse("https://ja3er.com/search/")
	// searchURL.Path = path.Join(searchURL.Path, ja3Response.JA3Hash)

	// resp, err = httpClient.Get(searchURL.String())
	// if err != nil {
	// 	fmt.Println(err)
	// 	panic(err)
	// }

	// body, err = ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	fmt.Println(err)
	// 	panic(err)
	// }

	// var out bytes.Buffer
	// err = json.Indent(&out, body, "", "\t")
	// if err != nil {
	// 	fmt.Println(err)
	// 	panic(err)
	// }
	// fmt.Println(out.String())
}