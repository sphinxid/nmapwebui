package handlers

import (
	"math"
	"strconv"

	"github.com/gin-gonic/gin"
)

type PaginatedResponse struct {
	Items   interface{} `json:"items"`
	Total   int64       `json:"total"`
	Page    int         `json:"page"`
	PerPage int         `json:"per_page"`
	Pages   int         `json:"pages"`
}

func parsePagination(c *gin.Context) (page, perPage int) {
	page = 1
	perPage = 20

	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	if pp, err := strconv.Atoi(c.Query("per_page")); err == nil {
		switch pp {
		case 20, 50, 100, 500:
			perPage = pp
		}
	}
	return
}

func paginatedResponse(items interface{}, total int64, page, perPage int) PaginatedResponse {
	pages := int(math.Ceil(float64(total) / float64(perPage)))
	if pages < 1 {
		pages = 1
	}
	return PaginatedResponse{
		Items:   items,
		Total:   total,
		Page:    page,
		PerPage: perPage,
		Pages:   pages,
	}
}

func offset(page, perPage int) int {
	return (page - 1) * perPage
}
