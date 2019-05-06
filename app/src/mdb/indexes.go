package mdb

import (
	"fmt"
	"time"
)

// *** thread unsafe ***
type StringUniqueIndex struct {
	valToPK     map[string]int
	lastUpdated int64
}

func NewStringUniqueIndex() *StringUniqueIndex {
	return &StringUniqueIndex{
		map[string]int{}, time.Now().Unix(),
	}
}

func (s *StringUniqueIndex) Find(val string) (int, bool) {
	ret, found := s.valToPK[val]
	return ret, found
}

func (s *StringUniqueIndex) Insert(val string, pk int) error {
	if _, found := s.valToPK[val]; found {
		return fmt.Errorf("%s already inserted", val)
	}
	s.valToPK[val] = pk
	s.lastUpdated = time.Now().Unix()
	return nil
}

func (s *StringUniqueIndex) Delete(val string) error {
	if _, found := s.valToPK[val]; !found {
		return fmt.Errorf("%s does not exist", val)
	}
	delete(s.valToPK, val)
	s.lastUpdated = time.Now().Unix()
	return nil
}

type StringIndex struct {
	valToPKs map[string][]int
}

func NewStringIndex() *StringIndex {
	return &StringIndex{map[string][]int{}}
}

func (s *StringIndex) Insert(val string, pk int) {
	s.valToPKs[val] = append(s.valToPKs[val], pk)
}

func (s *StringIndex) SelectPKs(val string) []int {
	return s.valToPKs[val]
}

type IntIndex struct {
	valToPKs map[int][]int
}

func NewIntIndex() *IntIndex {
	return &IntIndex{map[int][]int{}}
}

func (s *IntIndex) Insert(val int, pk int) {
	s.valToPKs[val] = append(s.valToPKs[val], pk)
}

func (s *IntIndex) SelectPKs(val int) []int {
	return s.valToPKs[val]
}

type Int64Index struct {
	valToPKs map[int64][]int
}

func NewInt64Index() *Int64Index {
	return &Int64Index{map[int64][]int{}}
}

func (s *Int64Index) Insert(val int64, pk int) {
	s.valToPKs[val] = append(s.valToPKs[val], pk)
}

func (s *Int64Index) SelectPKs(val int64) []int {
	return s.valToPKs[val]
}
