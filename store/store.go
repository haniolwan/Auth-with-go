package str

import "errors"

type Store struct {
	data map[string]string
}

func NewStore() *Store {
	return &Store{
		data: make(map[string]string)}
}

func (store *Store) Set(key, value string) error {
	store.data[key] = value
	return nil
}

func (store *Store) Get(key string) (string, error) {
	value, ok := store.data[key]

	if !ok {
		return "", errors.New("key not found")
	}
	return value, nil
}
