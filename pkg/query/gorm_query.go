package query

import (
	"gorm.io/gorm"
)

// GormQueryBuilder builds and manages SQL queries using GORM
type GormQueryBuilder struct {
	db        *gorm.DB
	filters   []filterCondition
	sorts     []sortCondition
	limit     int
	offset    int
	hasLimits bool
}

type filterCondition struct {
	query string
	args  interface{}
}

type sortCondition struct {
	field string
	order string
}

// NewGormQueryBuilder creates a new query builder with the given initial query
func NewGormQueryBuilder(initialQuery *gorm.DB) *GormQueryBuilder {
	return &GormQueryBuilder{
		db:        initialQuery,
		filters:   make([]filterCondition, 0),
		sorts:     make([]sortCondition, 0),
		hasLimits: false,
	}
}

// AddFilter adds a WHERE condition to the query
func (qb *GormQueryBuilder) AddFilter(query string, args interface{}) *GormQueryBuilder {
	qb.filters = append(qb.filters, filterCondition{
		query: query,
		args:  args,
	})
	return qb
}

// AddSort adds an ORDER BY condition to the query
func (qb *GormQueryBuilder) AddSort(field, order string) *GormQueryBuilder {
	qb.sorts = append(qb.sorts, sortCondition{
		field: field,
		order: order,
	})
	return qb
}

// SetPagination adds LIMIT and OFFSET to the query
func (qb *GormQueryBuilder) SetPagination(limit, offset int) *GormQueryBuilder {
	qb.limit = limit
	qb.offset = offset
	qb.hasLimits = true
	return qb
}

// BuildForCount builds a query suitable for counting total records
func (qb *GormQueryBuilder) BuildForCount() *gorm.DB {
	query := qb.db

	// Apply filters
	for _, filter := range qb.filters {
		query = query.Where(filter.query, filter.args)
	}

	return query
}

// Build constructs and returns the final GORM query
func (qb *GormQueryBuilder) Build() *gorm.DB {
	query := qb.db

	// Apply filters
	for _, filter := range qb.filters {
		query = query.Where(filter.query, filter.args)
	}

	// Apply sorts
	for _, sort := range qb.sorts {
		query = query.Order(sort.field + " " + sort.order)
	}

	// Apply pagination
	if qb.hasLimits {
		query = query.Limit(qb.limit).Offset(qb.offset)
	}

	return query
}
