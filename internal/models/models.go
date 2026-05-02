package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username     string         `gorm:"uniqueIndex;not null;size:64"`
	Email        string         `gorm:"uniqueIndex;not null;size:120"`
	PasswordHash string         `gorm:"not null;size:128"`
	Role         string         `gorm:"not null;size:20;default:'user'"`
	Active       bool           `gorm:"default:true"`
	Timezone     string         `gorm:"not null;size:50;default:'UTC'"`
	LastLogin    *time.Time
	TargetGroups []TargetGroup  `gorm:"foreignKey:UserID"`
	ScanTasks    []ScanTask     `gorm:"foreignKey:UserID"`
}

func (u *User) IsSuperAdmin() bool {
	return u.Role == "superadmin"
}

func (u *User) IsAdmin() bool {
	return u.Role == "admin" || u.Role == "superadmin"
}

type TargetGroup struct {
	gorm.Model
	Name        string    `gorm:"not null;size:64"`
	Description string    `gorm:"size:255"`
	UserID      uint      `gorm:"not null"`
	Targets     []Target  `gorm:"foreignKey:TargetGroupID;constraint:OnDelete:CASCADE;"`
	ScanTasks   []ScanTask `gorm:"many2many:task_target_groups;"`
}

type Target struct {
	gorm.Model
	Value         string `gorm:"not null;size:255"`
	TargetType    string `gorm:"not null;size:20;default:'ip'"`
	TargetGroupID uint   `gorm:"not null"`
}

type ScanTask struct {
	gorm.Model
	Name                string         `gorm:"not null;size:64"`
	Description         string         `gorm:"type:text"`
	ScanProfile         string         `gorm:"size:64"`
	CustomArgs          string         `gorm:"type:text"`
	UserID              uint           `gorm:"not null"`
	IsScheduled         bool           `gorm:"default:false"`
	ScheduleType        string         `gorm:"size:20"`
	ScheduleData        string         `gorm:"type:text"` // JSON
	ScheduleLastRun     *time.Time     `json:"schedule_last_run"`
	UseGlobalMaxReports bool           `gorm:"default:true"`
	MaxReports          *int
	TargetGroups        []TargetGroup  `gorm:"many2many:task_target_groups;"`
	ScanRuns            []ScanRun      `gorm:"foreignKey:TaskID;constraint:OnDelete:CASCADE;"`
}

type ScanRun struct {
	gorm.Model
	TaskID       uint         `gorm:"not null"`
	Task         ScanTask
	Status       string       `gorm:"not null;size:20;default:'queued'"`
	Progress     int          `gorm:"default:0"`
	StartedAt    *time.Time
	CompletedAt  *time.Time
	ErrorMessage string       `gorm:"type:text"`
	NmapPID      *int
	Report       *ScanReport  `gorm:"constraint:OnDelete:CASCADE;"`
}

type ScanReport struct {
	gorm.Model
	ScanRunID        uint          `gorm:"not null;uniqueIndex"`
	Summary          string        `gorm:"type:text"`
	XMLReportPath    string        `gorm:"size:255"`
	NormalReportPath string        `gorm:"size:255"`
	Hosts            []HostFinding `gorm:"foreignKey:ReportID;constraint:OnDelete:CASCADE;"`
}

type HostFinding struct {
	gorm.Model
	ReportID  uint          `gorm:"not null"`
	IPAddress string        `gorm:"not null;size:64"`
	Hostname  string        `gorm:"size:255"`
	Status    string        `gorm:"not null;size:20"`
	OSInfo    string        `gorm:"type:text"`
	Ports     []PortFinding `gorm:"foreignKey:HostID;constraint:OnDelete:CASCADE;"`
}

type PortFinding struct {
	gorm.Model
	HostID     uint   `gorm:"not null"`
	PortNumber int    `gorm:"not null"`
	Protocol   string `gorm:"not null;size:10"`
	State      string `gorm:"not null;size:20"`
	Service    string `gorm:"size:64"`
	Version    string `gorm:"size:255"`
}

type SystemSettings struct {
	Key   string `gorm:"primarykey;size:64"`
	Value string `gorm:"not null;type:text"`
}
