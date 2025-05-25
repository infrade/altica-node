package core

type Resolver struct {
	Store *RecordStore
}

func NewResolver(store *RecordStore) *Resolver {
	return &Resolver{Store: store}
}

func (r *Resolver) Resolve(domain string) (string, bool) {
	record, ok := r.Store.Get(domain)
	if !ok {
		return "", false
	}
	return record.Mappings["A"].(string), true
}
