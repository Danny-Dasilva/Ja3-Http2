package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func parseHTTP1(request []byte) Response {
	// Split the request into lines
	lines := strings.Split(string(request), "\r\n")

	// Split the first line into the method, path and http version
	firstLine := strings.Split(lines[0], " ")

	// Split the headers into an array
	var headers []string
	for _, line := range lines {
		if strings.Contains(line, ":") {
			headers = append(headers, line)
		}
	}

	if len(firstLine) != 3 {
		return Response{
			HTTPVersion: "--",
			Method:      "--",
			Path:        "--",
		}
	}
	return Response{
		HTTPVersion: firstLine[2],
		Path:        firstLine[1],
		Method:      firstLine[0],
		Http1: &Http1Details{
			Headers: headers,
		},
		TLS: Gja3,
	}
}

func parseHTTP2(f *http2.Framer, c chan ParsedFrame) {
	for {
		frame, err := f.ReadFrame()
		if err != nil {
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				return
			}
			log.Println("Error reading frame", err)
			return
		}

		p := ParsedFrame{}
		p.Type = frame.Header().Type.String()
		p.Stream = frame.Header().StreamID
		p.Length = frame.Header().Length

		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			p.Settings = []string{}
			frame.ForeachSetting(func(s http2.Setting) error {
				setting := fmt.Sprintf("%q", s)
				setting = strings.Replace(setting, "\"", "", -1)
				setting = strings.Replace(setting, "[", "", -1)
				setting = strings.Replace(setting, "]", "", -1)

				p.Settings = append(p.Settings, setting)
				return nil
			})
		case *http2.HeadersFrame:
			d := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
			d.SetEmitEnabled(true)
			h2Headers, err := d.DecodeFull(frame.HeaderBlockFragment())
			if err != nil {
				log.Println("Error decoding headers", err)
				return
			}

			for _, h := range h2Headers {
				h := fmt.Sprintf("%q: %q", h.Name, h.Value)
				h = strings.Trim(h, "\"")
				h = strings.Replace(h, "\": \"", ": ", -1)
				p.Headers = append(p.Headers, h)
			}
		case *http2.DataFrame:
			p.Payload = frame.Data()
		case *http2.WindowUpdateFrame:
			p.Increment = frame.Increment
		case *http2.PriorityFrame:
			// I really dont know why we need +1 here, but its one less than the actual value
			p.Weight = int(frame.PriorityParam.Weight + 1)
			p.DependsOn = int(frame.PriorityParam.StreamDep)
			if frame.PriorityParam.Exclusive {
				p.Exclusive = 1
			}
		}

		c <- p
	}
}

func handleConnection(conn net.Conn) {
	// Read the first line of the request
	// We only read the first line to determine if the connection is HTTP1 or HTTP2
	// If we know that it isnt HTTP2, we can read the rest of the request and then start processing it
	// If we know that it is HTTP2, we start the HTTP2 handler

	l := len([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	request := make([]byte, l)

	_, err := conn.Read(request)
	if err != nil {
		if !strings.Contains(err.Error(), "unknown certificate") {
			log.Println("Error reading request", err)
		}
		conn.Close()
		return
	}

	// Check if the first line is HTTP/2
	if string(request) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		// log.Println("HTTP/2 request")
		handleHTTP2(conn)
	} else {
		// log.Println("HTTP/1 request")

		// Read the rest of the request
		r2 := make([]byte, 1024-l)
		_, err := conn.Read(r2)
		if err != nil {
			log.Println(err)
			return
		}
		// Append it to the first line
		request = append(request, r2...)

		// Parse and handle the request
		details := parseHTTP1(request)
		details.IP = conn.RemoteAddr().String()
		handleHTTP1(conn, details)
	}
}

func handleHTTP1(conn net.Conn, resp Response) {
	// log.Println("Request:", resp.ToJson())
	// log.Println(len(resp.ToJson()))

	res1, ctype := Router(resp.Path, resp)

	res := "HTTP/1.1 200 OK\r\n"
	res += "Content-Length: " + fmt.Sprintf("%v\r\n", len(res1))
	res += "Content-Type: " + ctype + "; charset=utf-8\r\n"
	res += "Server: TrackMe\r\n"
	res += "\r\n"
	res += string(res1)
	res += "\r\n\r\n"

	conn.Write([]byte(res))
	conn.Close()
}

// https://stackoverflow.com/questions/52002623/golang-tcp-server-how-to-write-http2-data
func handleHTTP2(conn net.Conn) {
	// make a new framer to encode/decode frames
	fr := http2.NewFramer(conn, conn)
	c := make(chan ParsedFrame)
	var frames []ParsedFrame

	// Same settings that google uses
	fr.WriteSettings(
		http2.Setting{
			ID: http2.SettingInitialWindowSize, Val: 1048576,
		},
		http2.Setting{
			ID: http2.SettingMaxConcurrentStreams, Val: 100,
		},
		http2.Setting{
			ID: http2.SettingMaxHeaderListSize, Val: 65536,
		},
	)

	var frame ParsedFrame
	go parseHTTP2(fr, c)
	for {
		frame = <-c
		// log.Println(frame)
		frames = append(frames, frame)
		if frame.Type == "HEADERS" {
			break
		}
	}

	// get method and path from the first headers frame
	var path string
	var method string

	for _, h := range frame.Headers {
		if strings.HasPrefix(h, ":method") {
			method = strings.Split(h, ": ")[1]
		}
		if strings.HasPrefix(h, ":path") {
			path = strings.Split(h, ": ")[1]
		}
	}

	resp := Response{
		IP:          conn.RemoteAddr().String(),
		HTTPVersion: "h2",
		Path:        path,
		Method:      method,
		Http2: &Http2Details{
			SendFrames:            frames,
			AkamaiFingerprint:     GetAkamaiFingerprint(frames),
			AkamaiFingerprintHash: GetMD5Hash(GetAkamaiFingerprint(frames)),
		},
		TLS: Gja3,
	}

	res, ctype := Router(path, resp)

	// Prepare HEADERS
	hbuf := bytes.NewBuffer([]byte{})
	encoder := hpack.NewEncoder(hbuf)
	encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	encoder.WriteField(hpack.HeaderField{Name: "server", Value: "localhost-server"})
	encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(res))})
	encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: ctype})

	// Write HEADERS frame
	err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: frame.Stream, BlockFragment: hbuf.Bytes(), EndHeaders: true})
	if err != nil {
		log.Println("could not write headers: ", err)
		return
	}
	fr.WriteData(frame.Stream, true, res)
	conn.Close()
}
