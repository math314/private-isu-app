package mdb

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type UserStore struct {
	sync.RWMutex
	db      *sqlx.DB
	store   []*User
	deleted []bool

	accountNameIndex *StringUniqueIndex

	dbOpChan chan<- DBOperatorEntry
}

func NewUserStore(db *sqlx.DB) *UserStore {
	store := make([]*User, 0, 30000)
	deleted := make([]bool, 0, 30000)

	// id = 0 is unavailable
	store = append(store, nil)
	deleted = append(deleted, true)

	rows, err := db.Query(`SELECT * FROM users`)
	if err != nil {
		log.Fatal(err)
	}

	accountNameIndex := NewStringUniqueIndex()
	for rows.Next() {

		e := User{}
		var deletedF bool
		err := rows.Scan(&e.ID, &e.AccountName, &e.Passhash, &e.Authority, &e.DelFlg, &e.CreatedAt)
		if err != nil {
			log.Fatal(err)
		}
		for e.ID >= len(store) {
			store = append(store, nil)
			deleted = append(deleted, true)
		}
		store[e.ID] = &e
		deleted[e.ID] = deletedF

		accountNameIndex.Insert(e.AccountName, e.ID)
	}
	rows.Close()

	dbOpChan := make(chan DBOperatorEntry, 100)

	startDBOpfunc(db, dbOpChan)

	return &UserStore{
		RWMutex:          sync.RWMutex{},
		db:               db,
		store:            store,
		deleted:          deleted,
		accountNameIndex: accountNameIndex,
		dbOpChan:         dbOpChan,
	}
}

func (e *UserStore) Close() {
	close(e.dbOpChan)
}

func (e *UserStore) SelectFromId(id int) (*User, error) {
	e.RLock()
	defer e.RUnlock()

	if id >= len(e.store) {
		return nil, fmt.Errorf("not found")
	}

	tmp := *e.store[id]
	return &tmp, nil
}

func (e *UserStore) SelectFromName(name string) (*User, error) {
	e.RLock()
	defer e.RUnlock()

	id, found := e.accountNameIndex.Find(name)
	if !found {
		return nil, fmt.Errorf("not found")
	}
	if e.deleted[id] {
		return nil, fmt.Errorf("invalid")
	}

	tmp := *e.store[id]
	if tmp.DelFlg == 1 {
		return nil, fmt.Errorf("deleted")
	}
	return &tmp, nil
}

func (e *UserStore) SelectNonAdmins() []*User {
	// SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC
	e.RLock()
	defer e.RUnlock()

	var ret []*User

	for i, u := range e.store {
		if e.deleted[i] {
			continue
		}
		if u.Authority != 0 {
			continue
		}
		if u.DelFlg != 0 {
			continue
		}
		ret = append(ret, u)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].CreatedAt.After(ret[j].CreatedAt)
	})

	return ret
}

func (e *UserStore) DeleteUsers(ids []int) {
	//	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"
	e.Lock()
	defer e.Unlock()

	idStrs := []string{}
	for _, id := range ids {
		e.store[id].DelFlg = 1
		idStrs = append(idStrs, strconv.Itoa(id))
	}

	e.dbOpChan <- DBOperatorEntry{
		fmt.Sprintf("UPDATE `users` SET del_flg = 1 WHERE id in (%s)", strings.Join(idStrs, ",")), []interface{}{},
	}
}

func (e *UserStore) Insert(accountName, passHash string) (int, error) {
	e.Lock()
	defer e.Unlock()

	if _, found := e.accountNameIndex.Find(accountName); found {
		return 0, fmt.Errorf("already registered")
	}

	u := &User{
		ID:          len(e.store),
		DelFlg:      0,
		CreatedAt:   time.Now(),
		Authority:   0,
		AccountName: accountName,
		Passhash:    passHash,
	}

	e.store = append(e.store, u)
	e.deleted = append(e.deleted, false)
	e.accountNameIndex.Insert(accountName, u.ID)

	e.dbOpChan <- DBOperatorEntry{
		"INSERT INTO `users` (id, del_flg, created_at, authority, `account_name`, `passhash`) VALUES (?,?,?,?, ?,?)",
		[]interface{}{u.ID, u.DelFlg, u.CreatedAt, u.Authority, u.AccountName, u.Passhash},
	}
	return u.ID, nil
}

// account_name`, `passhash
