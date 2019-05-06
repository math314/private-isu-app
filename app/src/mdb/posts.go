package mdb

import (
	"github.com/jmoiron/sqlx"
	"log"
	"sort"
	"sync"
	"time"
)

type Post struct {
	ID        int       `db:"id"`
	UserID    int       `db:"user_id"`
	Body      string    `db:"body"`
	Mime      string    `db:"mime"`
	CreatedAt time.Time `db:"created_at"`
}

type PostStore struct {
	sync.RWMutex
	db          *sqlx.DB
	store       []*Post
	latest50Ids []int
	userIdIndex *IntIndex

	dbOpChan chan<- DBOperatorEntry
}

func (e *PostStore) Close() {
	close(e.dbOpChan)
}

func NewPostStore(db *sqlx.DB) *PostStore {
	store := make([]*Post, 0, 15000)

	// id = 0 is unavailable
	store = append(store, nil)

	rows, err := db.Query(`SELECT * FROM posts`)
	if err != nil {
		log.Fatal(err)
	}

	userIdIndex := NewIntIndex()
	for rows.Next() {

		e := Post{}
		err := rows.Scan(&e.ID, &e.UserID, &e.Mime, &e.Body, &e.CreatedAt)
		if err != nil {
			log.Fatal(err)
		}
		for e.ID >= len(store) {
			store = append(store, nil)
		}
		store[e.ID] = &e
		userIdIndex.Insert(e.UserID, e.ID)
	}
	rows.Close()

	var idsOrderByCreatedAt []int
	for i := 1; i < len(store); i++ {
		idsOrderByCreatedAt = append(idsOrderByCreatedAt, i)
	}
	sort.Slice(idsOrderByCreatedAt, func(i, j int) bool {
		return store[idsOrderByCreatedAt[i]].CreatedAt.After(store[idsOrderByCreatedAt[j]].CreatedAt)
	})

	dbOpChan := make(chan DBOperatorEntry, 100)

	startDBOpfunc(db, dbOpChan)

	return &PostStore{
		RWMutex:     sync.RWMutex{},
		db:          db,
		store:       store,
		latest50Ids: idsOrderByCreatedAt[:50],
		userIdIndex: userIdIndex,
		dbOpChan:    dbOpChan,
	}
}

func (e *PostStore) Select50OrderByCreatedAt() []*Post {
	e.RLock()
	defer e.RUnlock()

	var ret []*Post
	for _, id := range e.latest50Ids {
		tmp := *e.store[id]
		ret = append(ret, &tmp)
	}

	return ret
}

// db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC LIMIT 20", user.ID)
func (e *PostStore) SelectOrderByCreatedAtWhereUserId(userId int) []*Post {
	e.RLock()
	defer e.RUnlock()

	var ret []*Post
	for _, id := range e.userIdIndex.SelectPKs(userId) {
		tmp := *e.store[id]
		ret = append(ret, &tmp)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].CreatedAt.After(ret[j].CreatedAt)
	})

	return ret
}

// 	rerr := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC", t.Format(ISO8601_FORMAT))
func (e *PostStore) SelectOrderByCreatedAtWhereCreatedAt(createdAt time.Time) []*Post {
	e.RLock()
	defer e.RUnlock()

	var idsOrderByCreatedAt []int
	for i := 1; i < len(e.store); i++ {
		if e.store[i].CreatedAt.After(createdAt) {
			continue
		}
		idsOrderByCreatedAt = append(idsOrderByCreatedAt, i)
	}
	sort.Slice(idsOrderByCreatedAt, func(i, j int) bool {
		return e.store[idsOrderByCreatedAt[i]].CreatedAt.After(e.store[idsOrderByCreatedAt[j]].CreatedAt)
	})

	limit := 50
	if limit > len(idsOrderByCreatedAt) {
		limit = len(idsOrderByCreatedAt)
	}

	var ret []*Post
	for i := 0; i < limit; i++ {
		id := idsOrderByCreatedAt[i]
		ret = append(ret, e.store[id])
	}

	return ret
}

func (e *PostStore) SelectById(id int) []*Post {
	e.RLock()
	defer e.RUnlock()

	var ret []*Post
	ret = append(ret, e.store[id])
	return ret
}

func (e *PostStore) Insert(userId int, mime string, body string) int {
	e.Lock()
	defer e.Unlock()

	p := &Post{
		ID:        len(e.store),
		CreatedAt: time.Now(),
		UserID:    userId,
		Mime:      mime,
		Body:      body,
	}

	e.store = append(e.store, p)
	e.userIdIndex.Insert(p.UserID, p.ID)
	for i := 49; i > 0; i-- {
		e.latest50Ids[i] = e.latest50Ids[i-1]
	}
	e.latest50Ids[0] = p.ID

	e.dbOpChan <- DBOperatorEntry{
		"INSERT INTO posts (id, created_at, user_id, mime, body) VALUES(?,?,?,?,?)",
		[]interface{}{p.ID, p.CreatedAt, p.UserID, p.Mime, p.Body},
	}

	return p.ID
}
