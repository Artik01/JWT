package main

import (
	"net/http"
	"io"
	"fmt"
	"encoding/json"
	"crypto/sha256"
	"encoding/base64"
	"crypto/hmac"
	"time"
	"strings"
)

var Base64alphabet string = "QWEqweRTYrtyUIOuioPpASDasdFGHfghJKLjklZXCzxcVBNvbnMm?:1234567890"
var Encoder *base64.Encoding = base64.NewEncoding(Base64alphabet)

var Mutex chan int = make(chan int, 1)

type UserData struct {
	Login string    `json:"login"`
	Password string `json:"password"`
}

type User struct {
	ID int
	login string
	passwordHash [sha256.Size]byte
}

type Date struct {
	ExpDate int64	`json:"exp"`
}

var userDB []User

var TokenDB []string

func loginHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "OPTIONS, POST")
	w.Header().Add("Access-Control-Allow-Headers", "content-type")
	w.Header().Add("Access-Control-Allow-Origin","*")
	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
	} else if req.Method == "POST" {
		data, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {return }
		var v UserData
		err = json.Unmarshal(data, &v)
		if err != nil {fmt.Println(err); return}
		
		for _, u := range userDB {
			if u.login == v.Login && u.passwordHash == sha256.Sum256([]byte(v.Password)) {
				io.WriteString(w, createToken(u))
				return
			}
		}
		
		io.WriteString(w, "unknown")
	} else {
		w.WriteHeader(405)
	}
}

func createToken(user User) string {
	now := time.Now()
	Header:=
`{
	"alg":"HS256",
	"typ":"JWT"
}`
	
	Payload:=
`{
	"name":"`+user.login+`",
	"sub":"`+fmt.Sprint(user.ID)+`",
	"exp":`+fmt.Sprint(now.Add(time.Hour).Unix())+`
}`
	token:=Encoder.EncodeToString([]byte(Header))+"."+Encoder.EncodeToString([]byte(Payload))
	
	mac:=hmac.New(sha256.New,[]byte("Testtest"))//TODO:....................................................
	mac.Write([]byte(token))
	sum:=mac.Sum(nil)
	token+="."+Encoder.EncodeToString(sum)
	
	TokenDB = append(TokenDB,token)
	return token
}

func getHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "OPTIONS, GET")
	w.Header().Add("Access-Control-Allow-Headers", "content-type, token")
	w.Header().Add("Access-Control-Allow-Origin","*")
	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
	} else if req.Method == "GET" {
		token:= req.Header.Get("Token")
		
		for _, t := range TokenDB {
			if t == token {
				if time.Now().After(GetExp(token)) {
					DeleteToken(token)
					w.WriteHeader(401)
					return
				}
				io.WriteString(w, "success")
				return
			}
		}
		w.WriteHeader(401)
	} else {
		w.WriteHeader(405)
	}
}

func GetExp(t string) time.Time {
	t1:=strings.Index(t,".")
	t2:=strings.LastIndex(t,".")
	
	PayloadDecoded:=t[t1+1:t2]
	str, _:=Encoder.DecodeString(PayloadDecoded)
	var d Date
	json.Unmarshal(str,&d)
	return time.Unix(d.ExpDate,0)
}

func DeleteToken(token string) {
	<-Mutex
	i := 0
	var t string
	for i, t = range TokenDB {
		if t == token {
			break
		}
	}
	
	TokenDB = append(TokenDB[:i], TokenDB[i+1:]...)
	Mutex <- 1
}

func main() {
	Mutex <- 1
	userDB = append(userDB, User{1, "admin", sha256.Sum256([]byte("Test"))})
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/data", getHandler)
	
	err := http.ListenAndServe(":8080", nil)
	panic(err)
}
