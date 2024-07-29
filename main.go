package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type Book struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Author      string `json:"author"`
	PublishDate string `json:"publish_date"`
	ISBN        string `json:"isbn"`
}

func newBook(w http.ResponseWriter, r *http.Request) {
	var book Book

	err := json.NewDecoder(r.Body).Decode(&book)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not create: %v", err)
		w.Write([]byte("could not create a new book"))
		return
	}

	h := md5.New()
	io.WriteString(h, book.ISBN+book.PublishDate)
	book.ID = fmt.Sprintf("%x", h.Sum(nil))

	resp, err := json.MarshalIndent(book, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not marshal payload: %v", err)
		w.Write([]byte("could not save book data"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

type BookCheckout struct {
	BookID       string `json:"book_id"`
	User         string `json:"user"`
	CheckoutDate string `json:"checkout_date"`
	IsGenesis    bool   `json:"is_genesis"`
}

type Block struct {
	Position     int
	Data         BookCheckout
	Timestamp    string
	Hash         string
	PreviousHash string
}

func writeBlock(w http.ResponseWriter, r *http.Request) {
	var checkoutItem BookCheckout

	err := json.NewDecoder(r.Body).Decode(&checkoutItem)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not write block: %v", err)
		w.Write([]byte("could not write block"))
	}

	BlockChain.AddBlock(checkoutItem)
}

type Blockchain struct {
	blocks []*Block
}

func (b *Block) generateHash() {
	bytes, err := json.Marshal(b.Data)
	if err != nil {
		log.Printf("could not marshal: %v", err)
	}
	data := string(b.Position) + b.Timestamp + string(bytes) + b.PreviousHash
	hash := sha256.New()
	hash.Write([]byte(data))
	b.Hash = hex.EncodeToString(hash.Sum(nil))
}

func CreateBlock(previousBlock *Block, checkoutItem BookCheckout) *Block {
	block := &Block{}
	block.Position = previousBlock.Position + 1
	block.Timestamp = time.Now().String()
	block.PreviousHash = previousBlock.Hash
	block.generateHash()

	return block
}

func (bc *Blockchain) AddBlock(data BookCheckout) {
	previousBlock := bc.blocks[len(bc.blocks)-1]

	block := CreateBlock(previousBlock, data)

	if validBlock(block, previousBlock) {
		bc.blocks = append(bc.blocks, block)
	}
}

func validBlock(block, previousBlock *Block) bool {
	if previousBlock.Hash != block.PreviousHash {
		return false
	}

	if !block.validateHash(block.Hash) {
		return false
	}

	if previousBlock.Position+1 != block.Position {
		return false
	}

	return true
}

func (b *Block) validateHash(hash string) bool {
	b.generateHash()
	return b.Hash == hash
}

var BlockChain *Blockchain

func GenesisBlock() *Block {
	return CreateBlock(&Block{}, BookCheckout{IsGenesis: true})
}

func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{GenesisBlock()}}
}

func getBlockchain(w http.ResponseWriter, r *http.Request) {
	jbytes, err := json.MarshalIndent(BlockChain.blocks, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err)
		return
	}
	io.WriteString(w, string(jbytes))
}

func main() {
	BlockChain = NewBlockchain()

	r := mux.NewRouter()
	r.HandleFunc("/", getBlockchain).Methods("GET")
	r.HandleFunc("/", writeBlock).Methods("POST")
	r.HandleFunc("/new", newBook).Methods("POST")

	go func() {
		for _, block := range BlockChain.blocks {
			fmt.Printf("Previous hash: %x\n", block.PreviousHash)
			bytes, _ := json.MarshalIndent(block.Data, "", " ")
			fmt.Printf("Data: %v\n", string(bytes))
			fmt.Printf("Hash: %x\n", block.Hash)
			fmt.Println()
		}
	}()

	log.Println("Listening on port 3000")

	log.Fatal(http.ListenAndServe(":3000", r))
}
