package db

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB
var DBerr error

func init() {
	DB, DBerr = sql.Open("mysql", "root:@/quiz-app")
	if DBerr != nil {
		panic(DBerr.Error())
	}
	fmt.Println("Connection to the database successful!")
}
