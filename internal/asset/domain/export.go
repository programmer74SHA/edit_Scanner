package domain

// ExportType defines the type of export
type ExportType int

const (
	// FullExport exports all columns for assets
	FullExport ExportType = iota
	// SelectedColumnsExport exports only selected columns
	SelectedColumnsExport
)

// ExportData represents the data to be exported
type ExportData struct {
	Assets    []map[string]interface{}
	Ports     []map[string]interface{}
	VMwareVMs []map[string]interface{}
	AssetIPs  []map[string]interface{}
}
