// ack_audit reads only exact test-owned OSS namespaces supplied on stdin.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	_ "github.com/duckdb/duckdb-go/v2"
)

func main() {
	var files []string
	if err := json.NewDecoder(os.Stdin).Decode(&files); err != nil {
		panic(err)
	}
	if len(files) == 0 {
		fmt.Println("[]")
		return
	}
	db, err := sql.Open("duckdb", "")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if _, err := db.Exec("SET memory_limit='64MB'; SET threads=2"); err != nil {
		panic(err)
	}
	quoted := make([]string, len(files))
	for i, path := range files {
		quoted[i] = "'" + strings.ReplaceAll(path, "'", "''") + "'"
	}
	rows, err := db.Query("SELECT DISTINCT record_id FROM read_parquet([" + strings.Join(quoted, ",") + "], union_by_name=true) ORDER BY record_id")
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			panic(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		panic(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(ids); err != nil {
		panic(err)
	}
}
