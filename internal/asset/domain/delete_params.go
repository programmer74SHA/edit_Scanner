package domain

// DeleteParams encapsulates all possible parameters for asset deletion operations
type DeleteParams struct {
	UUID    *AssetUUID
	UUIDs   []AssetUUID
	Filters *AssetFilters
	Exclude bool
}

// NewDeleteParamsWithUUID creates DeleteParams for single asset deletion
func NewDeleteParamsWithUUID(uuid AssetUUID) DeleteParams {
	return DeleteParams{
		UUID: &uuid,
	}
}

// NewDeleteParamsWithUUIDs creates DeleteParams for multiple asset deletion
func NewDeleteParamsWithUUIDs(uuids []AssetUUID) DeleteParams {
	return DeleteParams{
		UUIDs: uuids,
	}
}

// NewDeleteParamsWithFilters creates DeleteParams for filtered deletion
func NewDeleteParamsWithFilters(filters AssetFilters) DeleteParams {
	return DeleteParams{
		Filters: &filters,
	}
}

// NewDeleteParamsWithFiltersExclude creates DeleteParams for filtered deletion with exclude IDs
func NewDeleteParamsWithFiltersExclude(filters AssetFilters, excludeUUIDs []AssetUUID) DeleteParams {
	return DeleteParams{
		Filters: &filters,
		UUIDs:   excludeUUIDs,
		Exclude: true,
	}
}

// NewDeleteParamsForAll creates DeleteParams for deleting all assets
func NewDeleteParamsForAll() DeleteParams {
	return DeleteParams{}
}

// NewDeleteParamsWithUUIDsExclude creates DeleteParams for deleting all assets except specified UUIDs
func NewDeleteParamsWithUUIDsExclude(uuids []AssetUUID) DeleteParams {
	return DeleteParams{
		UUIDs:   uuids,
		Exclude: true,
	}
}

// NewDeleteParamsWithUUIDsAndFilters creates DeleteParams for assets that match both IDs and filters
func NewDeleteParamsWithUUIDsAndFilters(uuids []AssetUUID, filters AssetFilters) DeleteParams {
	return DeleteParams{
		UUIDs:   uuids,
		Filters: &filters,
		Exclude: false,
	}
}
