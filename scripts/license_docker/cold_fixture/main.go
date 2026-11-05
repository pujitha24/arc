// Generate a new, synthetic-only Parquet object for OSS cold-read acceptance.
package main

import (
	"os"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"
)

func main() {
	schema := arrow.NewSchema([]arrow.Field{
		{Name: "time", Type: &arrow.TimestampType{Unit: arrow.Microsecond, TimeZone: "UTC"}},
		{Name: "host", Type: arrow.BinaryTypes.String},
		{Name: "value", Type: arrow.PrimitiveTypes.Float64},
	}, nil)
	b := array.NewRecordBuilder(memory.DefaultAllocator, schema)
	defer b.Release()
	for i := 0; i < 30; i++ {
		b.Field(0).(*array.TimestampBuilder).Append(arrow.Timestamp(1793577600000000 + int64(i)*1000000))
		b.Field(1).(*array.StringBuilder).Append("synthetic-only")
		b.Field(2).(*array.Float64Builder).Append(float64(i))
	}
	record := b.NewRecord()
	defer record.Release()
	f, err := os.OpenFile(os.Args[1], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w, err := pqarrow.NewFileWriter(schema, f, parquet.NewWriterProperties(parquet.WithCompression(0)),
		pqarrow.NewArrowWriterProperties(pqarrow.WithStoreSchema()))
	if err != nil {
		panic(err)
	}
	if err := w.Write(record); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
}
