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

// rows, err := db.DB.Query("SELECT * FROM USERS")

// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}
// 	for rows.Next() {
// 		var id int
// 		var name string
// 		var password string
// 		// Scan the values from the current row into variables
// 		err := rows.Scan(&id, &name, &password)
// 		if err != nil {
// 			fmt.Println("Error scanning row:", err)
// 			return
// 		}
// 		// Print the values
// 		fmt.Printf("ID: %d, Name: %s, Password: %s\n", id, name, password)
// 	}
// 	defer rows.Close()
