package main

import (
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "time"

    "github.com/olekukonko/tablewriter"
)

func generateTimeBasedKey() []byte {
    timestamp := time.Now().Format("20060102150405")
    hash := sha256.Sum256([]byte(timestamp))
    return hash[:]
}

func createHashMap(key []byte) [256]byte {
    var hashmap [256]byte
    for i := range hashmap {
        hashmap[i] = byte((i + int(key[i%len(key)])) % 256)
    }
    return hashmap
}

func encryptData(data []byte, hashmap [256]byte) []byte {
    encryptedData := make([]byte, len(data))
    for i, byteVal := range data {
        encryptedData[i] = hashmap[byteVal]
    }
    return encryptedData
}

func decryptData(data []byte, hashmap [256]byte) []byte {
    var reverseHashMap [256]byte
    for i, byteVal := range hashmap {
        reverseHashMap[byteVal] = byte(i)
    }
    decryptedData := make([]byte, len(data))
    for i, byteVal := range data {
        decryptedData[i] = reverseHashMap[byteVal]
    }
    return decryptedData
}

func encryptFolder(folderPath string) {
    key := generateTimeBasedKey()
    hashmap := createHashMap(key)

    files, err := ioutil.ReadDir(folderPath)
    if err != nil {
        fmt.Println(err)
        return
    }

    for _, file := range files {
        if file.IsDir() {
            continue
        }
        filePath := filepath.Join(folderPath, file.Name())
        originalData, err := ioutil.ReadFile(filePath)
        if err != nil {
            fmt.Println(err)
            continue
        }

        encryptedData := encryptData(originalData, hashmap)
        base64EncodedData := base64.StdEncoding.EncodeToString(encryptedData)

        err = ioutil.WriteFile(filePath+".enc", []byte(base64EncodedData), 0644)
        if err != nil {
            fmt.Println(err)
            continue
        }

        fmt.Printf("[!] ENCRYPTED %s to %s.enc\n", filePath, file.Name())
    }
}

func decryptFolder(folderPath string) {
    files, err := ioutil.ReadDir(folderPath)
    if err != nil {
        fmt.Println(err)
        return
    }

    for _, file := range files {
        if !file.IsDir() && filepath.Ext(file.Name()) == ".enc" {
            filePath := filepath.Join(folderPath, file.Name())
            encryptedData, err := ioutil.ReadFile(filePath)
            if err != nil {
                fmt.Println(err)
                continue
            }

            dataBytes, err := base64.StdEncoding.DecodeString(string(encryptedData))
            if err != nil {
                fmt.Println(err)
                continue
            }

            key := generateTimeBasedKey()
            hashmap := createHashMap(key)
            decryptedData := decryptData(dataBytes, hashmap)

            originalFilePath := filePath[:len(filePath)-4] // Remove '.enc' extension
            err = ioutil.WriteFile(originalFilePath, decryptedData, 0644)
            if err != nil {
                fmt.Println(err)
                continue
            }

            fmt.Printf("[!] DECRYPTED %s to %s\n", filePath, originalFilePath)
        }
    }
}

func printTable(files []os.FileInfo, action string) {
    var data [][]string
    for _, file := range files {
        if !file.IsDir() {
            data = append(data, []string{file.Name(), fmt.Sprintf("%d bytes", file.Size()), file.ModTime().Format(time.RFC3339)})
        }
    }

    table := tablewriter.NewWriter(os.Stdout)
    table.SetHeader([]string{"Filename", "Size", "Modified Time"})
    table.SetBorder(false) // Set to false for no border
    table.AppendBulk(data) // Add data
    fmt.Println()
    fmt.Printf("=== Files %s ===\n", action)
    fmt.Println()
    table.Render() // Print table
}

func printBoxMessage(message string) {
    border := "===================="
    fmt.Println(border)
    fmt.Printf("  %s\n", message)
    fmt.Println(border)
}

func main() {
    if len(os.Args) < 3 {
        printBoxMessage("Usage: go run file_encryption.go <action> <folder_path>")
        printBoxMessage("Actions: encrypt, decrypt")
        return
    }

    action := os.Args[1]
    folderPath := os.Args[2]

    files, err := ioutil.ReadDir(folderPath)
    if err != nil {
        fmt.Println(err)
        return
    }

    printTable(files, action)

    switch action {
    case "encrypt":
        encryptFolder(folderPath)
    case "decrypt":
        decryptFolder(folderPath)
    default:
        printBoxMessage("Unknown action. Use 'encrypt' or 'decrypt'.")
    }
}
