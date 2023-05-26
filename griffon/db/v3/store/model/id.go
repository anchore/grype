package model

import (
	"fmt"
	"time"

	v3 "github.com/nextlinux/griffon/griffon/db/v3"
)

const (
	IDTableName = "id"
)

type IDModel struct {
	BuildTimestamp string `gorm:"column:build_timestamp"`
	SchemaVersion  int    `gorm:"column:schema_version"`
}

func NewIDModel(id v3.ID) IDModel {
	return IDModel{
		BuildTimestamp: id.BuildTimestamp.Format(time.RFC3339Nano),
		SchemaVersion:  id.SchemaVersion,
	}
}

func (IDModel) TableName() string {
	return IDTableName
}

func (m *IDModel) Inflate() (v3.ID, error) {
	buildTime, err := time.Parse(time.RFC3339Nano, m.BuildTimestamp)
	if err != nil {
		return v3.ID{}, fmt.Errorf("unable to parse build timestamp (%+v): %w", m.BuildTimestamp, err)
	}

	return v3.ID{
		BuildTimestamp: buildTime,
		SchemaVersion:  m.SchemaVersion,
	}, nil
}
