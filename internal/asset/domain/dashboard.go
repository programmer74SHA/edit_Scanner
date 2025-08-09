package domain

// AssetCountData represents the asset count statistics for dashboard
type AssetCountData struct {
	Contents []AssetStatusCount `json:"contents"`
	Count    int                `json:"count"`
}

// AssetStatusCount represents asset status count
type AssetStatusCount struct {
	Source  string `json:"source"`
	Percent int    `json:"percent"`
}

// AssetPerScannerData represents assets grouped by scanner type
type AssetPerScannerData struct {
	Contents []ScannerTypeCount `json:"contents"`
}

// ScannerTypeCount represents asset count per scanner type
type ScannerTypeCount struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}

// LoggingCompletedData represents logging completed statistics by OS type
type LoggingCompletedData struct {
	Contents []OSLoggingStats `json:"contents"`
}

// OSLoggingStats represents logging statistics for a specific OS type
type OSLoggingStats struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
	Total  int    `json:"total"`
}

// AssetsPerSourceData represents assets distribution by OS source
type AssetsPerSourceData struct {
	Contents []AssetSourceStats `json:"contents"`
	Count    int                `json:"count"`
}

// AssetSourceStats represents asset percentage per OS source
type AssetSourceStats struct {
	Source  string `json:"source"`
	Percent int    `json:"percent"`
}
