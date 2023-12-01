package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoClient *mongo.Client
	mongoDB     *mongo.Database
	mongoCol    *mongo.Collection
)

func main() {
	

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	connectToMongoDB()
	
	token := os.Getenv("BOT_TOKEN")

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatal(err)
	}

	bot.Debug = true
	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates, err := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		if update.Message.IsCommand() {
			switch update.Message.Command() {
			case "add":
				handleAddCommand(bot, update)
			case "task":
				handleTaskCommand(bot, update)
			case "delete":
				handleDeleteCommand(bot, update)
			case "done":
				handleDoneCommand(bot, update)
			default:

			}
		}
	}
}

func handleAddCommand(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	userID := update.Message.From.ID
	task := update.Message.CommandArguments()

	hashedUserID := hashUserID(userID) // Hash the user ID

	key := deriveKey(userID)
	encryptedTask := encrypt(task, key)

	_, err := mongoCol.InsertOne(context.TODO(), bson.M{"hashedUserID": hashedUserID, "encryptedTask": encryptedTask})
	if err != nil {
		log.Println("Error inserting task into MongoDB:", err)
		return
	}

	reply := "Task added successfully!"
	msg := tgbotapi.NewMessage(update.Message.Chat.ID, reply)
	bot.Send(msg)
}

func handleDoneCommand(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	userID := update.Message.From.ID
	taskToMarkDone := update.Message.CommandArguments()

	hashedUserID := hashUserID(userID)
	key := deriveKey(userID)

	cursor, err := mongoCol.Find(context.TODO(), bson.M{"hashedUserID": hashedUserID})
	if err != nil {
		log.Println("Error retrieving tasks from MongoDB:", err)
		return
	}
	defer cursor.Close(context.Background())

	var foundTask bool
	for cursor.Next(context.Background()) {
		var result bson.M
		if err := cursor.Decode(&result); err != nil {
			log.Println("Error decoding task:", err)
			continue
		}

		encryptedTask, found := result["encryptedTask"].(string)
		if !found {
			log.Println("Encrypted task not found for the user")
			continue
		}

		decryptedTask := decrypt(encryptedTask, key)
		if decryptedTask == taskToMarkDone {
			_, delErr := mongoCol.DeleteOne(context.TODO(), bson.M{"_id": result["_id"]})
			if delErr != nil {
				log.Println("Error deleting task from MongoDB:", delErr)
				return
			}

			reply := "Task marked as done and deleted successfully!"
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, reply)
			bot.Send(msg)
			foundTask = true
			break // Exit loop after deleting the first occurrence of the task
		}
	}

	if !foundTask {
		reply := "Task not found!"
		msg := tgbotapi.NewMessage(update.Message.Chat.ID, reply)
		bot.Send(msg)
	}
}

func hashUserID(userID int) string {
	hash := sha256.Sum256([]byte(strconv.Itoa(userID)))
	return base64.URLEncoding.EncodeToString(hash[:]) // Encode the hash to a string before storing
}

func handleTaskCommand(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	userID := update.Message.From.ID
	key := deriveKey(userID)

	cursor, err := mongoCol.Find(context.TODO(), bson.M{"hashedUserID": hashUserID(userID)})
	if err != nil {
		log.Println("Error retrieving tasks from MongoDB:", err)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var result bson.M
		if err := cursor.Decode(&result); err != nil {
			log.Println("Error decoding task:", err)
			continue
		}

		encryptedTask, found := result["encryptedTask"].(string)
		if !found {
			log.Println("Encrypted task not found for the user")
			continue
		}

		decryptedTask := decrypt(encryptedTask, key)

		msg := tgbotapi.NewMessage(update.Message.Chat.ID, decryptedTask)
		bot.Send(msg)
	}
}

func handleDeleteCommand(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	userID := update.Message.From.ID

	hashedUserID := hashUserID(userID)

	// Delete all tasks that match the hashed user ID
	_, err := mongoCol.DeleteMany(context.TODO(), bson.M{"hashedUserID": hashedUserID})
	if err != nil {
		log.Println("Error deleting tasks from MongoDB:", err)
		return
	}

	reply := "All tasks deleted successfully!"
	msg := tgbotapi.NewMessage(update.Message.Chat.ID, reply)
	bot.Send(msg)
}

func deriveKey(userID int) []byte {
	hash := sha256.Sum256([]byte(strconv.Itoa(userID)))
	return hash[:]
}

func encrypt(text string, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("Error creating cipher block:", err)
		return ""
	}

	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Println("Error generating IV:", err)
		return ""
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))

	return base64.URLEncoding.EncodeToString(ciphertext)
}

func decrypt(encryptedText string, key []byte) string {
	cipherText, err := base64.URLEncoding.DecodeString(encryptedText)
	if err != nil {
		log.Println("Error decoding ciphertext:", err)
		return ""
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("Error creating cipher block:", err)
		return ""
	}

	iv := cipherText[:aes.BlockSize]
	stream := cipher.NewCTR(block, iv)

	decrypted := make([]byte, len(cipherText[aes.BlockSize:]))
	stream.XORKeyStream(decrypted, cipherText[aes.BlockSize:])

	return string(decrypted)
}

func connectToMongoDB() {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")

	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	mongoClient = client
	mongoDB = client.Database(os.Getenv("DB_NAME"))
	mongoCol = mongoDB.Collection(os.Getenv("DB_COLLECTION"))
}
