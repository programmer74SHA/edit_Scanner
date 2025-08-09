package http

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// GetScanJobs retrieves scan jobs based on filter, pagination, and sorting
func GetScanJobs(svcGetter ServiceGetter[*service.ScanJobService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.GetJobsRequest

		// Set pagination parameters
		limit := c.QueryInt("limit", 10)
		req.Limit = int32(limit)

		page := c.QueryInt("page", 0)
		req.Page = int32(page)

		if req.Limit < 1 {
			req.Limit = 10
		}
		if req.Page < 0 {
			req.Page = 0
		}

		// Extract sorts and filters from query parameters
		queries := c.Queries()
		req.Sort = extractSorts(queries)
		req.Filter = extractScanJobFilters(queries)

		res, err := srv.GetJobs(c.UserContext(), &req)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		return c.JSON(res)
	}
}

// GetScanJobByID retrieves a single scan job by its ID
func GetScanJobByID(svcGetter ServiceGetter[*service.ScanJobService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		id, err := c.ParamsInt("id")
		if err != nil {
			return fiber.ErrBadRequest
		}

		res, err := srv.GetJobByID(c.UserContext(), &pb.GetJobByIDRequest{Id: int64(id)})
		if err != nil {
			if errors.Is(err, service.ErrInvalidScanJobUUID) {
				return fiber.ErrBadRequest
			}
			if errors.Is(err, service.ErrScanJobNotFound) {
				return fiber.ErrNotFound
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(res)
	}
}

// CancelScanJob cancels a running scan job
func CancelScanJob(svcGetter ServiceGetter[*service.ScanJobService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		// Get job ID from URL parameter
		id := c.Params("id")
		if id == "" {
			logger.WarnContext(c.UserContext(), "Cancel scan job: Job ID is empty")
			return c.Status(fiber.StatusBadRequest).JSON(map[string]interface{}{
				"success": false,
				"error":   "Job ID is required",
			})
		}

		logger.InfoContext(c.UserContext(), "Attempting to cancel scan job with ID: %s", id)

		// Create the request
		req := &pb.CancelScanJobRequest{
			Id: id,
		}

		// Call the service to cancel the scan job
		response, err := srv.CancelScanJob(c.UserContext(), req)
		if err != nil {
			logger.ErrorContext(c.UserContext(), "Failed to cancel scan job: %v", err)

			if errors.Is(err, service.ErrScanJobNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(map[string]interface{}{
					"success": false,
					"error":   "Scan job not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			})
		}

		if !response.Success {
			return c.Status(fiber.StatusInternalServerError).JSON(map[string]interface{}{
				"success": false,
				"error":   response.ErrorMessage,
			})
		}

		logger.InfoContext(c.UserContext(), "Successfully cancelled scan job with ID: %s", id)

		// Return consistent JSON response
		return c.Status(fiber.StatusOK).JSON(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"job_id":    id,
				"cancelled": true,
				"message":   "Scan job cancelled successfully",
			},
		})
	}
}

// DiffJobs compares two scan jobs and returns the differences in assets
func DiffJobs(svcGetter ServiceGetter[*service.ScanJobService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.DiffJobsRequest

		// Parse job IDs from query parameter (e.g., ids=1,2)
		idsStr := c.Query("ids")
		if idsStr == "" {
			return fiber.NewError(fiber.StatusBadRequest, "ids parameter is required")
		}

		// Parse comma-separated IDs
		idStrs := strings.Split(idsStr, ",")
		if len(idStrs) != 2 {
			return fiber.NewError(fiber.StatusBadRequest, "Exactly 2 job IDs must be provided in the ids parameter")
		}

		ids := make([]int64, 2)
		for i, idStr := range idStrs {
			id, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
			if err != nil {
				return fiber.NewError(fiber.StatusBadRequest, "Invalid job ID format")
			}
			ids[i] = id
		}
		req.Ids = ids

		// Parse type parameter (new or missing)
		assetType := c.Query("type", "new")
		if assetType != "new" && assetType != "missing" {
			return fiber.NewError(fiber.StatusBadRequest, "type parameter must be 'new' or 'missing'")
		}
		req.Type = assetType

		// Set pagination parameters
		limit := c.QueryInt("limit", 25)
		req.Limit = int32(limit)

		page := c.QueryInt("page", 0)
		req.Page = int32(page)

		if req.Limit < 1 {
			req.Limit = 25
		}
		if req.Page < 0 {
			req.Page = 0
		}

		// Extract sorts from query parameters
		queries := c.Queries()
		req.Sort = extractDiffJobSorts(queries)

		res, err := srv.DiffJobs(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidScanJobUUID) {
				return fiber.NewError(fiber.StatusBadRequest, "Invalid job ID format")
			}
			if errors.Is(err, service.ErrScanJobNotFound) {
				return fiber.NewError(fiber.StatusNotFound, "One or both scan jobs not found")
			}
			if errors.Is(err, service.ErrJobNotComplete) {
				return fiber.NewError(fiber.StatusBadRequest, "Both jobs must have 'Completed' status for diffing")
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(res)
	}
}

// ExportJobDiff exports the diff between two scan jobs as a CSV file
func ExportJobDiff(svcGetter ServiceGetter[*service.ScanJobService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.ExportJobDiffRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		// Validate that exactly 2 job IDs are provided
		if len(req.GetIds()) != 2 {
			return fiber.NewError(fiber.StatusBadRequest, "Exactly 2 job IDs must be provided in the ids array")
		}

		csvData, err := srv.ExportJobDiff(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidScanJobUUID) {
				return fiber.NewError(fiber.StatusBadRequest, "Invalid job ID format")
			}
			if errors.Is(err, service.ErrScanJobNotFound) {
				return fiber.NewError(fiber.StatusNotFound, "One or both scan jobs not found")
			}
			if errors.Is(err, service.ErrJobNotComplete) {
				return fiber.NewError(fiber.StatusBadRequest, "Both jobs must have 'Completed' status for diffing")
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		filename := fmt.Sprintf("job_diff_export_%s.csv", time.Now().Format("20060102_150405"))

		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Set("Content-Type", "text/csv")

		return c.Send(csvData)
	}
}
