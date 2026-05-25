package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/anchore/grype/grype/db/v6"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

type sqlLogger struct {
	writer *bufio.Writer
}

func (l *sqlLogger) LogMode(level logger.LogLevel) logger.Interface { return l }
func (l *sqlLogger) Info(ctx context.Context, msg string, data ...interface{}) {}
func (l *sqlLogger) Warn(ctx context.Context, msg string, data ...interface{}) {}
func (l *sqlLogger) Error(ctx context.Context, msg string, data ...interface{}) {}
func (l *sqlLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	sql, _ := fc()
	if sql != "" {
		// PostgreSQL strictly forbids NULL values in composite primary keys.
		// Since these specifier overrides tables use pointer fields (*string) as part of the primary key
		// and contain NULL values in SQLite, we remove the composite PRIMARY KEY constraint to allow NULLs in Postgres.
		if strings.Contains(sql, "CREATE TABLE \"operating_system_specifier_overrides\"") ||
			strings.Contains(sql, "CREATE TABLE \"package_specifier_overrides\"") {
			if idx := strings.LastIndex(sql, ",PRIMARY KEY"); idx != -1 {
				sql = sql[:idx] + ")"
			}
		}
		l.writer.WriteString(sql + ";\n")
	}
}

func formatSQLValue(val interface{}, isBool bool) string {
	if val == nil {
		return "NULL"
	}

	if isBool {
		switch v := val.(type) {
		case bool:
			if v {
				return "true"
			}
			return "false"
		case int:
			if v != 0 {
				return "true"
			}
			return "false"
		case int8:
			if v != 0 {
				return "true"
			}
			return "false"
		case int16:
			if v != 0 {
				return "true"
			}
			return "false"
		case int32:
			if v != 0 {
				return "true"
			}
			return "false"
		case int64:
			if v != 0 {
				return "true"
			}
			return "false"
		case uint:
			if v != 0 {
				return "true"
			}
			return "false"
		case uint8:
			if v != 0 {
				return "true"
			}
			return "false"
		case uint16:
			if v != 0 {
				return "true"
			}
			return "false"
		case uint32:
			if v != 0 {
				return "true"
			}
			return "false"
		case uint64:
			if v != 0 {
				return "true"
			}
			return "false"
		case float32:
			if v != 0 {
				return "true"
			}
			return "false"
		case float64:
			if v != 0 {
				return "true"
			}
			return "false"
		case string:
			vl := strings.ToLower(v)
			if vl == "true" || vl == "1" || vl == "t" {
				return "true"
			}
			return "false"
		}
	}

	switch v := val.(type) {
	case string:
		escaped := strings.ReplaceAll(v, "'", "''")
		escaped = strings.ReplaceAll(escaped, "\\", "\\\\")
		return "'" + escaped + "'"
	case []byte:
		escaped := strings.ReplaceAll(string(v), "'", "''")
		escaped = strings.ReplaceAll(escaped, "\\", "\\\\")
		return "'" + escaped + "'"
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%f", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case time.Time:
		if v.IsZero() {
			return "NULL"
		}
		return "'" + v.UTC().Format(time.RFC3339Nano) + "'"
	default:
		escaped := strings.ReplaceAll(fmt.Sprintf("%v", v), "'", "''")
		return "'" + escaped + "'"
	}
}

func main() {
	sqlitePath := "/Users/stanislavkhoshov/Library/Caches/grype/db/6/vulnerability.db"
	dumpFile := "vulnerability_postgres.sql"

	startTime := time.Now()

	fmt.Println("⏳ Подключение к SQLite...")
	dbSrc, err := gorm.Open(sqlite.Open(sqlitePath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Ошибка подключения к SQLite: %v", err)
	}

	// Создаем файл дампа с буферизацией для максимальной скорости записи на диск
	f, err := os.Create(dumpFile)
	if err != nil {
		log.Fatalf("Не удалось создать файл: %v", err)
	}
	defer f.Close()

	writer := bufio.NewWriterSize(f, 1024*1024) // Буфер 1 МБ
	defer writer.Flush()

	fmt.Printf("📝 Запись заголовков и схемы в %s...\n", dumpFile)

	writer.WriteString("-- Инициализация NOCASE для Postgres\n")
	writer.WriteString("CREATE COLLATION IF NOT EXISTS NOCASE (provider = icu, locale = 'und-u-ks-level2', deterministic = false);\n\n")
	writer.WriteString("SET session_replication_role = 'replica';\n\n")

	// Настраиваем DryRun Postgres с логгером в буфер (для DDL)
	dbDry, _ := gorm.Open(postgres.Open("host=localhost port=5432 user=postgres dbname=postgres sslmode=disable"), &gorm.Config{
		DryRun: true,
		Logger: &sqlLogger{writer: writer},
	})

	models := v6.Models()

	// 1. Автоматическая миграция DDL (создает таблицы и индексы в дампе)
	fmt.Println("🏗️ Генерация DDL таблиц и индексов...")
	err = dbDry.AutoMigrate(models...)
	if err != nil {
		log.Fatalf("Ошибка миграции: %v", err)
	}
	writer.WriteString("\n")

	// Получаем список ВСЕХ таблиц из SQLite (включая многие-ко-многим join-таблицы типа package_cpes)
	tables, err := dbSrc.Migrator().GetTables()
	if err != nil {
		log.Fatalf("Не удалось прочитать список таблиц: %v", err)
	}

	// 2. Выгружаем данные через пакетный импорт (Bulk Insert) на чистом SQL
	for _, tableName := range tables {
		// Пропускаем встроенные таблицы sqlite
		if strings.HasPrefix(tableName, "sqlite_") {
			continue
		}

		fmt.Printf("📦 Выгрузка таблицы %s...\n", tableName)
		writer.WriteString(fmt.Sprintf("-- Данные для таблицы: %s\n", tableName))

		// Находим соответствующую модель GORM, чтобы узнать оригинальные Go-типы полей (включая bool)
		var modelSchema *schema.Schema
		for _, model := range models {
			stmt := &gorm.Statement{DB: dbDry}
			_ = stmt.Parse(model)
			if stmt.Schema.Table == tableName {
				modelSchema = stmt.Schema
				break
			}
		}

		// Получаем имена колонок из SQLite
		var columns []struct {
			Name string `gorm:"column:name"`
			Type string `gorm:"column:type"`
		}
		err := dbSrc.Raw(fmt.Sprintf("PRAGMA table_info(%q)", tableName)).Scan(&columns).Error
		if err != nil {
			log.Fatalf("Не удалось получить колонки для %s: %v", tableName, err)
		}

		colNames := make([]string, len(columns))
		isColBool := make([]bool, len(columns))
		for i, col := range columns {
			colNames[i] = `"` + col.Name + `"`
			
			// Определяем, является ли колонка булевой
			isBool := false
			if modelSchema != nil {
				field := modelSchema.FieldsByDBName[col.Name]
				if field != nil {
					// Проверяем тип данных в модели Go
					isBool = field.DataType == "bool"
				}
			}
			// Резервный вариант на случай, если это служебная/связующая таблица (join table)
			if !isBool {
				isBool = strings.Contains(strings.ToLower(col.Type), "bool")
			}
			isColBool[i] = isBool
		}
		insertHeader := fmt.Sprintf("INSERT INTO %q (%s) VALUES ", tableName, strings.Join(colNames, ", "))

		batchSize := 5000
		offset := 0

		for {
			// Читаем сырые данные пачкой в виде map[string]interface{}
			var rows []map[string]interface{}
			err := dbSrc.Table(tableName).Limit(batchSize).Offset(offset).Find(&rows).Error
			if err != nil {
				log.Fatalf("Ошибка чтения SQLite: %v", err)
			}

			rowsCount := len(rows)
			if rowsCount == 0 {
				break
			}

			// Строим пакетный (Bulk) INSERT на 5000 строк
			var valuesLines []string
			for _, row := range rows {
				valStrings := make([]string, len(columns))
				for i, col := range columns {
					valStrings[i] = formatSQLValue(row[col.Name], isColBool[i])
				}
				valuesLines = append(valuesLines, "("+strings.Join(valStrings, ", ")+")")
			}

			// Записываем единый Bulk Insert в файл
			writer.WriteString(insertHeader + strings.Join(valuesLines, ", ") + ";\n")

			offset += rowsCount
			if rowsCount < batchSize {
				break
			}
		}
		writer.WriteString("\n")
	}

	writer.WriteString("SET session_replication_role = 'origin';\n")
	
	// Сбрасываем буфер в файл
	writer.Flush()

	fmt.Printf("🎉 Дамп успешно сохранен в файл: %s (за %v)\n", dumpFile, time.Since(startTime))
}
