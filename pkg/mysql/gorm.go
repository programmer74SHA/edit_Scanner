package mysql

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	pkgLogger "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DBConnOptions struct {
	Host     string
	Port     uint
	Username string
	Password string
	Database string
}

func NewMysqlConnection(cfg DBConnOptions) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
	)
	return gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Discard,
	})
}

func GormMigrations(db *gorm.DB) {
	// Temporarily disable foreign key checks for migration
	if err := db.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
		pkgLogger.Warn("Could not disable foreign key checks: %v", err)
	}
	defer db.Exec("SET FOREIGN_KEY_CHECKS = 1")

	// Define migration order to respect foreign key dependencies
	// Base tables first (no dependencies)
	err := db.AutoMigrate(
		&types.User{},
		&types.Vendors{},
		&types.InterfaceTypes{},
		&types.NmapProfile{}, // Add NmapProfile early since it has no dependencies
	)
	if err != nil {
		pkgLogger.Fatal("failed to migrate base tables: %v", err)
	}

	// Asset-related tables (depends on vendors)
	err = db.AutoMigrate(
		&types.Assets{},
		&types.IPs{},
		&types.Port{},
		&types.VMwareVM{},
		&types.AssetScanJob{},
	)
	if err != nil {
		pkgLogger.Fatal("failed to migrate asset tables: %v", err)
	}

	// VCenter infrastructure tables (datacenters first, then dependent tables)
	err = db.AutoMigrate(
		&types.VCenterDatacenter{},
		&types.VCenterHost{},
		&types.VCenterDatastore{},
		&types.VCenterNetwork{},
		&types.VCenterCluster{},
		&types.VCenterHostIP{},
		&types.VCenterHostNIC{},
		&types.VCenterVirtualSwitch{},
		&types.VMDatastoreRelation{},
		&types.VMNetworkRelation{},
		&types.HostDatastoreRelation{},
	)
	if err != nil {
		pkgLogger.Fatal("failed to migrate vCenter tables: %v", err)
	}

	// Scanner-related tables (NmapMetadata now depends on NmapProfile)
	err = db.AutoMigrate(
		&types.Scanner{},
		&types.ScanJob{},
		&types.NmapMetadata{},
		&types.NmapIPScan{},
		&types.NmapNetworkScan{},
		&types.NmapRangeScan{},
		&types.DomainMetadata{},
		&types.VcenterMetadata{},
		&types.FirewallMetadata{},
		&types.SwitchMetadata{},
		&types.SwitchNeighbor{},
		&types.NessusMetadata{},
		&types.Schedule{},
	)
	if err != nil {
		pkgLogger.Fatal("failed to migrate scanner tables: %v", err)
	}

	// Firewall-specific tables (depends on assets and interface_types)
	err = db.AutoMigrate(
		&types.FirewallDetails{},
		&types.Zones{},
		&types.Interfaces{},
		&types.VLANs{},
		&types.VLANInterface{},
		&types.ZoneDetails{},
		&types.FirewallPolicy{},
	)
	if err != nil {
		pkgLogger.Fatal("failed to migrate firewall tables: %v", err)
	}

	// Vulnerability-related tables (depends on assets)
	err = db.AutoMigrate(
		&types.Vulnerability{},
		&types.NessusScan{},
		&types.AssetVulnerability{},
	)
	if err != nil {
		pkgLogger.Fatal("failed to migrate vulnerability tables: %v", err)
	}

	// Session table
	err = db.AutoMigrate(&types.Session{})
	if err != nil {
		pkgLogger.Fatal("failed to migrate session table: %v", err)
	}

	// Add custom constraints that are not automatically handled by GORM tags
	if err := addCustomConstraints(db); err != nil {
		pkgLogger.Warn("Failed to add custom constraints: %v", err)
	}

	pkgLogger.Info("All database migrations completed successfully")
}

// addCustomConstraints adds custom constraints and fixes foreign keys
func addCustomConstraints(db *gorm.DB) error {
	pkgLogger.Info("Adding custom unique constraints...")

	// Apply unique constraints for firewall tables
	constraints := types.UniqueConstraints{}
	if err := constraints.ApplyConstraints(db); err != nil {
		pkgLogger.Warn("Error applying unique constraints: %v", err)
		return err
	}

	pkgLogger.Info("Custom constraints setup completed")
	return nil
}

func SeedData(db *gorm.DB, hashPassword func(string) (string, error)) {
	// Seed user data
	var userCount int64
	db.Model(&types.User{}).Count(&userCount)
	if userCount == 0 {
		hpassword, err := hashPassword("P@ssw0rd")
		if err != nil {
			pkgLogger.Error("Failed to hash password in seed data: %v", err)
			return
		}

		// Create empty strings for nullable fields
		emptyFirstName := ""
		emptyLastName := ""
		emptyEmail := ""

		user := types.User{
			ID:        uuid.New().String(),
			FirstName: &emptyFirstName,
			LastName:  &emptyLastName,
			Username:  "admin",
			Password:  hpassword,
			Email:     &emptyEmail,
			Role:      "admin",
			CreatedAt: time.Now(),
			Sessions:  []types.Session{},
		}

		result := db.Create(&user)
		if result.Error != nil {
			pkgLogger.Error("Failed to seed user data: %v", result.Error)
			return
		}
		pkgLogger.Info("User seed data inserted successfully.")
	}

	// Seed Nmap profiles
	seedNmapProfiles(db)

	// Seed firewall vendor data
	seedFirewallVendors(db)

	// Seed interface types
	seedInterfaceTypes(db)

	pkgLogger.Info("All seed data insertion completed successfully")
}

// Helper function for nullable string pointers
func stringPtr(s string) *string {
	return &s
}

func seedNmapProfiles(db *gorm.DB) {
	pkgLogger.Info("Seeding Nmap profiles...")

	defaultProfiles := []types.NmapProfile{
		{
			Name:        "Quick Scan",
			Description: stringPtr("Fast scan of top 100 ports using SYN scan"),
			Arguments:   types.NmapArguments{"-sS", "-T4", "--top-ports", "100", "-oX", "-"},
			IsDefault:   true,
			IsSystem:    true,
			CreatedBy:   stringPtr("system"),
			CreatedAt:   time.Now(),
		},
		{
			Name:        "Comprehensive Scan",
			Description: stringPtr("Thorough scan with version detection, script scanning, and OS detection"),
			Arguments:   types.NmapArguments{"-sS", "-sV", "-sC", "-O", "-T4", "--top-ports", "1000", "-oX", "-"},
			IsDefault:   false,
			IsSystem:    true,
			CreatedBy:   stringPtr("system"),
			CreatedAt:   time.Now(),
		},
		{
			Name:        "Stealth Scan",
			Description: stringPtr("Slow and stealthy scan to avoid detection"),
			Arguments:   types.NmapArguments{"-sS", "-T2", "-f", "--top-ports", "1000", "-oX", "-"},
			IsDefault:   false,
			IsSystem:    true,
			CreatedBy:   stringPtr("system"),
			CreatedAt:   time.Now(),
		},
		{
			Name:        "UDP Scan",
			Description: stringPtr("UDP port scan for top ports"),
			Arguments:   types.NmapArguments{"-sU", "--top-ports", "1000", "-T4", "-oX", "-"},
			IsDefault:   false,
			IsSystem:    true,
			CreatedBy:   stringPtr("system"),
			CreatedAt:   time.Now(),
		},
		{
			Name:        "Port Range Scan",
			Description: stringPtr("Scan specific port range (1-1000)"),
			Arguments:   types.NmapArguments{"-sS", "-T4", "-p", "1-1000", "-oX", "-"},
			IsDefault:   false,
			IsSystem:    true,
			CreatedBy:   stringPtr("system"),
			CreatedAt:   time.Now(),
		},
	}

	for _, profile := range defaultProfiles {
		var existingProfile types.NmapProfile
		result := db.Where("name = ?", profile.Name).First(&existingProfile)

		if result.Error != nil {
			if err := db.Create(&profile).Error; err != nil {
				pkgLogger.Error("Failed to insert Nmap profile %s: %v", profile.Name, err)
			} else {
				pkgLogger.Info("Inserted Nmap profile: %s", profile.Name)
			}
		} else {
			pkgLogger.Info("Nmap profile already exists: %s", profile.Name)
		}
	}
}

// seedFirewallVendors inserts initial firewall vendor data
func seedFirewallVendors(db *gorm.DB) {
	pkgLogger.Info("Seeding firewall vendors...")

	vendors := []types.Vendors{
		{VendorName: "Cisco", VendorCode: "CSC"},
		{VendorName: "Fortinet", VendorCode: "FORTI"},
		{VendorName: "VMware", VendorCode: "VMW"},
		{VendorName: "Microsoft", VendorCode: "MST"},
		{VendorName: "Linux", VendorCode: "LNX"},
		{VendorName: "Generic", VendorCode: "GEN"},
		{VendorName: "Unknown", VendorCode: "UNK"},
	}

	for _, vendor := range vendors {
		var existingVendor types.Vendors
		result := db.Where("vendor_code = ?", vendor.VendorCode).First(&existingVendor)

		if result.Error != nil {
			if err := db.Create(&vendor).Error; err != nil {
				pkgLogger.Error("Failed to insert vendor %s: %v", vendor.VendorCode, err)
			} else {
				pkgLogger.Info("Inserted vendor: %s", vendor.VendorName)
			}
		} else {
			pkgLogger.Info("Vendor already exists: %s", vendor.VendorName)
		}
	}
}

// seedInterfaceTypes inserts initial interface type data
func seedInterfaceTypes(db *gorm.DB) {
	pkgLogger.Info("Seeding interface types...")

	interfaceTypes := []types.InterfaceTypes{
		{TypeName: "ethernet", Description: "Physical Ethernet interface"},
		{TypeName: "vlan", Description: "VLAN subinterface"},
		{TypeName: "loopback", Description: "Loopback interface"},
		{TypeName: "tunnel", Description: "Tunnel interface (VPN, GRE, etc.)"},
		{TypeName: "aggregate", Description: "Link aggregation/bonding"},
		{TypeName: "redundant", Description: "Redundant interface"},
		{TypeName: "virtual-wire", Description: "Virtual wire interface"},
		{TypeName: "layer2", Description: "Layer 2 interface"},
		{TypeName: "management", Description: "Management interface"},
		{TypeName: "ha", Description: "High Availability interface"},
		{TypeName: "virtual-router", Description: "Virtual router interface"},
	}

	for _, ifType := range interfaceTypes {
		var existingType types.InterfaceTypes
		result := db.Where("type_name = ?", ifType.TypeName).First(&existingType)

		if result.Error != nil {
			if err := db.Create(&ifType).Error; err != nil {
				pkgLogger.Error("Failed to insert interface type %s: %v", ifType.TypeName, err)
			} else {
				pkgLogger.Info("Inserted interface type: %s", ifType.TypeName)
			}
		} else {
			pkgLogger.Info("Interface type already exists: %s", ifType.TypeName)
		}
	}
}
