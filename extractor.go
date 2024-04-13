package main

import (
        "crypto/hmac"
        "crypto/md5"
        "encoding/hex"
        "fmt"
        "io/ioutil"
        "os"
        "regexp"
        "time"
)

var (
        REGEX_UTF16 = regexp.MustCompile(`\x00([a-f0-9]\x00){8}`)
        REGEX_UTF8  = regexp.MustCompile(`\x00([a-f0-9]){8}`)
        MAGIC_V1    = []byte{0xEA, 0xD0}
)

func main() {
        args := os.Args[1:]

        if len(args) < 1 {
                fmt.Println("Usage:\ngo run extractor.go <path> [packet]")
                return
        }

        romPath := args[0]
        var testPacket string
        if len(args) > 1 {
                testPacket = args[1]
        }

        start := time.Now()
        fmt.Print("Parsing rom for access keys...")

        romContents, err := ioutil.ReadFile(romPath)
        if err != nil {
                fmt.Println("Error reading ROM file:", err)
                return
        }

        utf16Matches := REGEX_UTF16.FindAllString(string(romContents), -1)
        utf8Matches := REGEX_UTF8.FindAllString(string(romContents), -1)

        var possibleKeys []string
        possibleKeys = append(possibleKeys, utf16Matches...)
        possibleKeys = append(possibleKeys, utf8Matches...)

        for i, match := range possibleKeys {
                possibleKeys[i] = regexp.MustCompile(`\x00`).ReplaceAllString(match, "")
        }

        possibleKeys = uniqueStrings(possibleKeys)

        if len(possibleKeys) == 0 {
                fmt.Println("No possible access keys found")
                fmt.Println("Parsing took:", time.Since(start))
                return
        }

        if testPacket == "" {
                fmt.Println("No test packet found")
                fmt.Println("Possible access keys (the correct key is usually one of the first):")
                fmt.Println(possibleKeys)
                fmt.Println("Parsing took:", time.Since(start))
                return
        }

        packetBytes, err := hex.DecodeString(testPacket)
        if err != nil {
                fmt.Println("Error decoding test packet:", err)
                return
        }

        if len(packetBytes) >= 2 && packetBytes[0] == MAGIC_V1[0] && packetBytes[1] == MAGIC_V1[1] {
                checkPacketV1(possibleKeys, packetBytes, start)
        } else {
                checkPacketV0(possibleKeys, packetBytes, start)
        }
}

func checkPacketV0(possibleKeys []string, packetBytes []byte, start time.Time) {
        oldCheck := packetBytes[len(packetBytes)-1]

        for _, key := range possibleKeys {
                fmt.Println("Trying key:", key)
                newCheck := calcChecksumV0(key, packetBytes[:len(packetBytes)-1])

                if newCheck == oldCheck {
                        fmt.Println("Found working access key:", key)
                        fmt.Println("Parsing took:", time.Since(start))
                        return
                }
        }

        fmt.Println("No possible access keys found for provided test packet. Was the test packet sent from the provided title?")
        fmt.Println("Parsing took:", time.Since(start))
}

func calcChecksumV0(key string, data []byte) byte {
        var number uint8
        keyBytes := []byte(key)

        for _, b := range keyBytes {
                number += b
        }

        sum := uint32(0)
        for i := 0; i < len(data)-3; i += 4 {
                sum += uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
        }

        remaining := len(data) % 4
        if remaining > 0 {
                var lastSum uint32
                for i := len(data) - remaining; i < len(data); i++ {
                        lastSum |= uint32(data[i]) << uint32((i%4)*8)
                }
                sum += lastSum
        }

        for i := (len(data) / 4) * 4; i < len(data); i++ {
                number += data[i]
        }

        sumBytes := make([]byte, 4)
        sumBytes[0] = byte(sum)
        sumBytes[1] = byte(sum >> 8)
        sumBytes[2] = byte(sum >> 16)
        sumBytes[3] = byte(sum >> 24)

        for _, b := range sumBytes {
                number += b
        }

        return number
}

func checkPacketV1(possibleKeys []string, packetBytes []byte, start time.Time) {
    header := packetBytes[2:14]
    expectedSignature := packetBytes[14:30]
    optionsSize := header[1]

    headerSection := header[4:]
    options := packetBytes[30 : 30+optionsSize]

    for _, key := range possibleKeys {
        fmt.Println("Trying key:", key)
        keyBytes := []byte(key)
        signatureKey := md5Sum(key)
        signatureBase := uint32(0)
        for _, b := range keyBytes {
            signatureBase += uint32(b)
        }
        signatureBaseBytes := make([]byte, 4)
        signatureBaseBytes[0] = byte(signatureBase)
        signatureBaseBytes[1] = byte(signatureBase >> 8)
        signatureBaseBytes[2] = byte(signatureBase >> 16)
        signatureBaseBytes[3] = byte(signatureBase >> 24)

        mac := hmac.New(md5.New, signatureKey)
        mac.Write(headerSection)
        mac.Write([]byte{}) // session key not present in SYN packet
        mac.Write(signatureBaseBytes)
        mac.Write([]byte{}) // connection signature not present in SYN packet
        mac.Write(options)
        mac.Write([]byte{}) // payload not present in SYN packet

        calculatedSignature := mac.Sum(nil)

        if hmac.Equal(expectedSignature, calculatedSignature) {
            fmt.Println("Found working access key:", key)
            fmt.Println("Parsing took:", time.Since(start))
            return
        }
    }

    fmt.Println("No possible access keys found for provided test packet. Was the test packet sent from the provided title?")
    fmt.Println("Parsing took:", time.Since(start))
}

func md5Sum(text string) []byte {
	hash := md5.Sum([]byte(text))
	return hash[:]
}

func uniqueStrings(slice []string) []string {
    keys := make(map[string]bool)
    list := []string{}
    for _, entry := range slice {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }
    return list
}

