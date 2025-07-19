package main

import (
	"bytes"
	// "compress/gzip"
	"fmt"
	// "io"
	"log"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type Http2Context struct {
    Framer           *http2.Framer
    Decoder          *hpack.Decoder
    LastHeaders      map[uint64][]byte
    Reader           *bytes.Buffer
    ContentEncodings map[uint64]string
}

func handleFrame(f http2.Frame, ctx *Http2Context) {
	switch frame := f.(type) {
	case *http2.DataFrame:
		data := frame.Data()
		// Frame payload (raw data)
		// if ctx.ContentEncodings[uint64(frame.StreamID)] == "gzip" {
		// 	reader, err := gzip.NewReader(bytes.NewReader(data))
		// 	if err != nil {
		// 		fmt.Println("Gzip reader error:", err)
		// 		return
		// 	}
		// 	defer reader.Close()

		// 	decoded, err := io.ReadAll(reader)
		// 	fmt.Printf("DATA frame (gzipped & decoded): %s\n", string(decoded))
		// 	if err != nil {
		// 		fmt.Println("Gzip decompress error:", err)
		// 		// ctx.GzipHeaders[uint64(frame.StreamID)] = reader.Header
		// 		return
		// 	}
		// } else {
			fmt.Printf("DATA frame: %s\n", string(data))
		// }

	case *http2.HeadersFrame:
		fmt.Printf("HEADERS frame:\n\n")
		hbf := frame.HeaderBlockFragment()

		headers := make([]hpack.HeaderField, 0)
		ctx.Decoder.SetEmitFunc(func(f hpack.HeaderField) {
			headers = append(headers, f)
		})

		if _, err := ctx.Decoder.Write(hbf); err != nil {
			fmt.Println("HPACK decoding error:", err)
			return
		}
		if err := ctx.Decoder.Close(); err != nil {
			fmt.Println("HPACK decoding close error:", err)
			return
		}

		for _, hf := range headers {
			fmt.Printf("%s: %s\n", hf.Name, hf.Value)
			if strings.ToLower(hf.Name) == "content-encoding" {
				ctx.ContentEncodings[uint64(frame.StreamID)] = hf.Value
			}
		}

	case *http2.SettingsFrame:
		var settingNames = map[http2.SettingID]string{
			http2.SettingHeaderTableSize:      "SETTINGS_HEADER_TABLE_SIZE",
			http2.SettingEnablePush:           "SETTINGS_ENABLE_PUSH",
			http2.SettingMaxConcurrentStreams: "SETTINGS_MAX_CONCURRENT_STREAMS",
			http2.SettingInitialWindowSize:    "SETTINGS_INITIAL_WINDOW_SIZE",
			http2.SettingMaxFrameSize:         "SETTINGS_MAX_FRAME_SIZE",
			http2.SettingMaxHeaderListSize:    "SETTINGS_MAX_HEADER_LIST_SIZE",
		}
		frame.ForeachSetting(func(s http2.Setting) error {
			name := settingNames[s.ID] 
			if name != ""{
				fmt.Printf("Setting: %s = %v\n", name, s.Val)
			}else{
				fmt.Printf("Setting: %v = %v\n", s.ID, s.Val)
			}
			return nil
		})
		
		fmt.Println("SETTINGS frame received")

	case *http2.WindowUpdateFrame:
		fmt.Println("WindowUpdateFrame received")

	default:
		fmt.Printf("Unhandled frame type: %T\n", frame)
	}
	fmt.Printf("\n\n");
}

func decodeHttp2(byteData []byte, eventId uint64, ctx *Http2Context) { //framer *http2.Framer, decoder *hpack.Decoder, lastHeaders *map[uint64][]byte,  reader *bytes.Buffer
	// Check for HTTP/2 preface and handle accordingly
	if len(byteData) >= len(http2.ClientPreface) {
		if bytes.Equal(byteData[:len(http2.ClientPreface)], []byte(http2.ClientPreface)) {
			byteData = byteData[len(http2.ClientPreface):]
		}
	}
	bytesRead := 0
	for {
		if len(byteData) <= 0{
			break
		}
		// Trim the already processed data
		byteData = byteData[bytesRead:]
		bytesRead = 0

		// If lastHeaders[eventId] is non-nil, append and pass data to framer
		if ctx.LastHeaders[eventId] != nil {
			// Extract the frame header (first 9 bytes)
			header := (ctx.LastHeaders[eventId])[:9]

			// Calculate header values
			length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])

			if len(byteData) < length{
				fmt.Printf("Illegal data, data length left: %d, length in header: %d\n", len(byteData), length)
				return
			}

			_, err := ctx.Reader.Write(ctx.LastHeaders[eventId])
			if err != nil {
				log.Println("Error writing lastHeaders:", err)
				return
			}

			n, err := ctx.Reader.Write(byteData[:length])
			if err != nil {
				log.Println("Error writing byteData:", err)
				return
			}

			// frameType := header[3]
			// flags := header[4]
			// streamID := int(header[5])<<24 | int(header[6])<<16 | int(header[7])<<8 | int(header[8])
			// fmt.Printf("Length %d, frameType %d, flags %d, streamID %d\n", length, frameType, flags, streamID)

			bytesRead += n

			// Feed combined data into framer for further processing
			frame,err := ctx.Framer.ReadFrame()
			if(err!=nil){
				fmt.Printf("Encountered an error while trying to read frame: %s\n", err)
				continue
			}
			fmt.Println(frame)
			handleFrame(frame, ctx)
			ctx.LastHeaders[eventId] = nil;
		}else{
			// If the data length is less than 9, store it for later (e.g., incomplete frame)
			if len(byteData) >= 9 {
				// Extract the frame header (first 9 bytes)
				header := byteData[:9]

				// Calculate header values
				length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
				frameType := header[3]
				flags := header[4]
				streamID := int(header[5])<<24 | int(header[6])<<16 | int(header[7])<<8 | int(header[8])

				fmt.Printf("Length %d, frameType %d, flags %d, streamID %d\n", length, frameType, flags, streamID)

				// Validate frame type
				frameTypeStr := http2.FrameType(frameType).String()
				if strings.HasPrefix(frameTypeStr, "UNKNOWN") {
					log.Printf("Invalid frame type %d in frame header\n", frameType)
					break
				}

				// Check for invalid frame length (too large)
				if length > 16384 {
					log.Println("Frame length exceeds max allowed (16384 bytes), discarding data.")
					break
				}

				// If length is 0, it's a frame with no payload, process it
				if length == 0 {
					_, err := ctx.Reader.Write(header)
					if err != nil {
						log.Println("Error writing header:", err)
						return
					}

					// Update bytesRead for the next iteration
					bytesRead += 9

					// Pass to framer
					frame,err := ctx.Framer.ReadFrame()
					if(err!=nil){
						fmt.Printf("Encountered an error while trying to read frame: %s\n", err)
						continue
					}
					fmt.Println(frame)
					handleFrame(frame, ctx)
					ctx.LastHeaders[eventId] = nil;
				} else if len(byteData) >= 9+length {
					// If enough data exists for a full frame
					_, err := ctx.Reader.Write(header)
					if err != nil {
						log.Println("Error writing header:", err)
						return
					}
					// Write frame payload
					_, err = ctx.Reader.Write(byteData[9 : 9+length])

					// Update bytesRead for the next iteration
					bytesRead += 9 + length

					if err != nil {
						log.Println("Error writing frame payload:", err)
						return
					}
					// Feed the frame to framer for processing
					frame,err := ctx.Framer.ReadFrame()
					if(err!=nil){
						fmt.Printf("Encountered an error while trying to read frame: %s\n", err)
						continue
					}
					fmt.Println(frame)
					fmt.Printf("Parsed a frame, therefore removing element in lastHeaders map\n")
					ctx.LastHeaders[eventId] = nil;
					handleFrame(frame, ctx)
				} else if len(byteData)-9 < length {
					fmt.Printf("Header was sent alone, saving it and waiting for frame payload\n")
					bytesRead += 9
					ctx.LastHeaders[eventId] = header
					break
				}
			}else{
				// fmt.Printf("No header in queue and data len < min header length (9)\n")
				break
			}
		}
	}
}