package mdb

import (
	"github.com/jmoiron/sqlx"
	"log"
	"sort"
	"sync"
	"time"
)

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
}

type CommentStore struct {
	sync.RWMutex
	db          *sqlx.DB
	store       []*Comment
	postIdIndex *IntIndex
	userIdIndex *IntIndex

	dbOpChan chan<- DBOperatorEntry
}

func NewCommentStore(db *sqlx.DB) *CommentStore {
	store := make([]*Comment, 0, 150000)

	// id = 0 is unavailable
	store = append(store, nil)

	rows, err := db.Query(`SELECT * FROM comments`)
	if err != nil {
		log.Fatal(err)
	}

	postIndex := NewIntIndex()
	userIdIndex := NewIntIndex()
	for rows.Next() {

		e := Comment{}
		err := rows.Scan(&e.ID, &e.PostID, &e.UserID, &e.Comment, &e.CreatedAt)
		if err != nil {
			log.Fatal(err)
		}
		for e.ID >= len(store) {
			store = append(store, nil)
		}
		store[e.ID] = &e

		postIndex.Insert(e.PostID, e.ID)
		userIdIndex.Insert(e.UserID, e.ID)
	}
	rows.Close()

	dbOpChan := make(chan DBOperatorEntry, 100)

	startDBOpfunc(db, dbOpChan)

	return &CommentStore{
		RWMutex:     sync.RWMutex{},
		db:          db,
		store:       store,
		postIdIndex: postIndex,
		userIdIndex: userIdIndex,
		dbOpChan:    dbOpChan,
	}
}

func (e *CommentStore) Close() {
	close(e.dbOpChan)
}

// SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?
func (e *CommentStore) SelectCountWherePostId(postId int) int {
	e.RLock()
	defer e.RUnlock()

	return len(e.postIdIndex.SelectPKs(postId))
}

// 		query := "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC"
//		if !allComments {
//			query += " LIMIT 3"
//		}
func (e *CommentStore) SelectCommentOrderByCreatedAt(postId int, limit int) []*Comment {
	e.RLock()
	defer e.RUnlock()

	var ret []*Comment

	for _, pid := range e.postIdIndex.SelectPKs(postId) {
		tmp := *e.store[pid]
		ret = append(ret, &tmp)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].CreatedAt.After(ret[j].CreatedAt)
	})

	if limit > 0 {
		if limit > len(ret) {
			limit = len(ret)
		}
		ret = ret[:limit]
	}

	return ret
}

// 	cerr := db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
func (e *CommentStore) SelectCountWhereUserId(userId int) int {
	e.RLock()
	defer e.RUnlock()

	return len(e.userIdIndex.SelectPKs(userId))
}

// 	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
//	db.Exec(query, postID, me.ID, r.FormValue("comment"))

func (e *CommentStore) Insert(postId, userId int, comment string) {
	e.Lock()
	defer e.Unlock()

	c := &Comment{
		ID:        len(e.store),
		CreatedAt: time.Now(),
		PostID:    postId,
		UserID:    userId,
		Comment:   comment,
	}

	e.store = append(e.store, c)
	e.postIdIndex.Insert(c.PostID, c.ID)
	e.userIdIndex.Insert(c.UserID, c.ID)

	e.dbOpChan <- DBOperatorEntry{
		"INSERT INTO `comments` (id, `post_id`, `user_id`, `comment`, created_at) VALUES (?,?,?,?,?)",
		[]interface{}{c.ID, c.PostID, c.UserID, c.Comment, c.CreatedAt},
	}
}
