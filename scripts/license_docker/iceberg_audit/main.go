// iceberg_audit is an independent, read-only directory-table reader for fixtures.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	iceio "github.com/apache/iceberg-go/io"
	_ "github.com/apache/iceberg-go/io/gocloud/s3"
	"github.com/apache/iceberg-go/table"
	_ "github.com/duckdb/duckdb-go/v2"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: iceberg-audit TABLE_URI FIXTURE_S3_ENDPOINT")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	location := strings.TrimSuffix(os.Args[1], "/")
	props := map[string]string{iceio.S3EndpointURL: os.Args[2], iceio.S3ForceVirtualAddressing: "false", iceio.S3Region: "us-east-1", iceio.S3AccessKeyID: "local-test", iceio.S3SecretAccessKey: "local-test"}
	factory := iceio.LoadFSFunc(props, location)
	fs, err := factory(ctx)
	if err != nil {
		panic(err)
	}
	f, err := fs.Open(location + "/metadata/version-hint.text")
	if err != nil {
		panic(err)
	}
	hint, err := io.ReadAll(io.LimitReader(f, 128))
	f.Close()
	if err != nil {
		panic(err)
	}
	version, err := strconv.Atoi(strings.TrimSpace(string(hint)))
	if err != nil || version < 1 {
		panic("invalid directory-table hint")
	}
	metadata := fmt.Sprintf("%s/metadata/v%d.metadata.json", location, version)
	tbl, err := table.NewFromLocation(ctx, table.Identifier{"audit", "events"}, metadata, factory, nil)
	if err != nil {
		panic(err)
	}
	tasks, err := tbl.Scan().PlanFiles(ctx)
	if err != nil {
		panic(err)
	}
	files := map[string]bool{}
	for _, task := range tasks {
		files[task.File.FilePath()] = true
	}
	quoted := make([]string, 0, len(files))
	remote := false
	for path := range files {
		quoted = append(quoted, "'"+strings.ReplaceAll(path, "'", "''")+"'")
		remote = remote || strings.HasPrefix(path, "s3://")
	}
	sort.Strings(quoted)
	db, err := sql.Open("duckdb", "")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "SET memory_limit='64MB'; SET threads=2"); err != nil {
		panic(err)
	}
	if remote {
		endpoint, err := url.Parse(os.Args[2])
		if err != nil || endpoint.Host == "" {
			panic("invalid fixture endpoint")
		}
		statement := "LOAD httpfs; CREATE SECRET fixture_s3 (TYPE S3, KEY_ID 'local-test', SECRET 'local-test', REGION 'us-east-1', ENDPOINT '" + strings.ReplaceAll(endpoint.Host, "'", "''") + "', URL_STYLE 'path', USE_SSL false)"
		if _, err := db.ExecContext(ctx, statement); err != nil {
			panic(err)
		}
	}
	ids := []string{}
	if len(quoted) > 0 {
		rows, err := db.QueryContext(ctx, "SELECT record_id FROM read_parquet(["+strings.Join(quoted, ",")+"], union_by_name=true) ORDER BY record_id")
		if err != nil {
			panic(err)
		}
		defer rows.Close()
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
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Version int      `json:"version"`
		IDs     []string `json:"ids"`
	}{version, ids}); err != nil {
		panic(err)
	}
}
