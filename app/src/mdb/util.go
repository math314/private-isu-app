package mdb

import (
	"github.com/jmoiron/sqlx"
	"log"
)

type DBOperatorEntry struct {
	query string
	args  []interface{}
}

func startDBOpfunc(db *sqlx.DB, dbOps <-chan DBOperatorEntry) {
	go func() {
		for val := range dbOps {
			log.Printf("query = %s, args = %v", val.query, val.args)
			_, err := db.Exec(val.query, val.args...)
			if err != nil {
				log.Print(err)
			}
		}
	}()
}
