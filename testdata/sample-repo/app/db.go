package main

import (
	"database/sql"
	"fmt"
)

func buildQuery(userID string) string {
	query := "SELECT * FROM users WHERE id = " + userID
	return query
}

func main() {
	db, _ := sql.Open("postgres", "user=postgres dbname=test")
	defer db.Close()
	fmt.Println("Query:", buildQuery("123"))
}
