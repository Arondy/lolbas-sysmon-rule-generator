# LOLBAS Sysmon Rule Generator

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🌍 *Read this in other languages: [English](README.md), [Русский](README-ru.md)*

---

CLI-утилита на Python для автоматической генерации правил обнаружения Sysmon на основе данных [LOLBAS Project](https://lolbas-project.github.io/) (Living Off The Land Binaries and Scripts).

## Обзор

LOLBAS Project документирует легитимные бинарные файлы Windows, которые могут быть использованы злоумышленниками. Этот инструмент автоматизирует создание правил Sysmon для этих бинарных файлов, обогащая их маппингом техник MITRE ATT&CK.

### Ключевые возможности

- **Автоматическая генерация правил** — Получает данные LOLBAS Project и генерирует XML-правила Sysmon
- **Несколько типов событий** — Поддержка ProcessCreate (Event ID 1), ProcessAccess (Event ID 10) и FileCreate (Event ID 11)
- **Два типа правил**:
  - **CommandLine правила** — Более точное обнаружение с использованием executable + флагов командной строки
  - **Fallback правила** — Более широкое обнаружение только по имени executable
- **Интеграция с MITRE ATT&CK** — Обогащение правил идентификаторами и названиями техник
- **Гибкая конфигурация** — TOML-конфигурация для категорий, маппингов и префиксов
- **Поддержка слияния** — Объединение сгенерированных правил с существующими конфигурациями Sysmon
- **Дедупликация** — Опциональный флаг `--unique-rules` для пропуска дублирующихся правил между категориями

## Установка

### Требования

- Python 3.11 или выше
- pip или иной менеджер пакетов Python

### Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/yourusername/lolbas-sysmon-generator.git
cd lolbas-sysmon-generator
```

2. Установите зависимости через pip:
```bash
pip install -r requirements.txt
```

3. Установка через Poetry (альтернатива):
```bash
pip install poetry
poetry install --no-root
```

## Использование

### Базовое использование

Генерация правил для всех включённых категорий:
```bash
python -m lolbas_sysmon
```

Это выполнит:
1. Загрузку данных LOLBAS (или использование кэшированного `lolbas.json`)
2. Загрузку данных MITRE ATT&CK (или использование кэшированного `enterprise-attack.json`)
3. Генерацию правил и сохранение в `lolbas_rules.xml`

### Параметры командной строки

```
usage: lolbas_sysmon [-h] [-i INPUT] [-o OUTPUT] [-f] [-c CONFIG]
                     [--category CATEGORY] [--dry-run] [--lolbas-json PATH]
                     [--mitre-json PATH] [--unique-rules]

Генерация правил обнаружения Sysmon из данных LOLBAS

options:
  -h, --help            Показать справку и выйти
  -i, --input INPUT     Входной XML-файл конфигурации Sysmon для слияния
  -o, --output OUTPUT   Путь к выходному XML-файлу (по умолчанию: lolbas_rules.xml)
  -f, --force           Заменять существующие правила вместо пропуска
  -c, --config CONFIG   Путь к TOML-файлу конфигурации
  --category CATEGORY   Список категорий через запятую (например, Execute,Dump)
  --dry-run             Вывести сгенерированные правила без сохранения в файл
  --lolbas-json PATH    Путь к локальному JSON-файлу LOLBAS
  --mitre-json PATH     Путь к локальному JSON-файлу MITRE ATT&CK
  --unique-rules        Пропускать дублирующиеся правила для одного executable в рамках одного event type
```

### Примеры

**Генерация правил для конкретных категорий:**
```bash
python -m lolbas_sysmon --category "Execute,Download,Dump"
```

**Предпросмотр правил без сохранения (dry-run):**
```bash
python -m lolbas_sysmon --dry-run
```

**Слияние с существующей конфигурацией Sysmon:**
```bash
python -m lolbas_sysmon -i sysmonconfig.xml -o merged_config.xml
```

**Принудительная замена существующих правил при слиянии:**
```bash
python -m lolbas_sysmon -i sysmonconfig.xml -o merged_config.xml --force
```

**Генерация дедуплицированных правил:**
```bash
python -m lolbas_sysmon --unique-rules
```

**Показать покрытые и отсутствующие LOLBins:**
```bash
python -m lolbas_sysmon --coverage -i sysmonconfig.xml --show-covered --show-missing
```

**Использование пользовательской конфигурации:**
```bash
python -m lolbas_sysmon -c my_config.toml
```

**Принудительное обновление данных LOLBAS и MITRE:**
```bash
python -m lolbas_sysmon --update-data
```

### Использование Docker

Сборка образа:
```bash
docker build -t lolbas-sysmon .
```

Генерация правил (standalone):
```bash
docker run --rm -v .:/app lolbas-sysmon python -m lolbas_sysmon -o /app/lolbas_rules.xml
```

Слияние с существующей конфигурацией Sysmon:
```bash
docker run --rm -v .:/app lolbas-sysmon \
  python -m lolbas_sysmon -i /app/sysmonconfig.xml -o /app/merged_config.xml
```

Использование пользовательской конфигурации и дедупликации:
```bash
docker run --rm -v .:/app lolbas-sysmon \
  python -m lolbas_sysmon -c /app/config.toml --unique-rules -o /app/lolbas_rules.xml
```

## Конфигурация

Инструмент использует TOML-файл конфигурации (`config.toml` по умолчанию).

### Категории

Включение или отключение категорий LOLBAS для генерации правил:

```toml
[categories]
enabled = [
  "ADS",
  "AWL Bypass",
  "Compile",
  "Credentials",
  "Decode",
  "Download",
  "Dump",
  "Execute",
  # ... другие категории
]
```

Доступные категории:
| Категория | Описание |
|----------|----------|
| ADS | Операции с Alternate Data Stream |
| AWL Bypass | Обход белых списков приложений |
| Compile | Компиляция кода |
| Credentials | Доступ к учётным данным/дампинг |
| Decode | Декодирование закодированных payload'ов |
| Download | Загрузка файлов из интернета |
| Dump | Дампинг памяти/процессов |
| Encode | Кодирование payload'ов |
| Execute | Выполнение произвольного кода/команд |
| Reconnaissance | Перечисление системы/сети |
| Tamper | Изменение системных настроек |
| UAC Bypass | Обход User Account Control |
| Upload | Эксфильтрация данных |

### Маппинг типов событий

Сопоставление категорий с типами событий Sysmon:

```toml
[mappings]
"Execute" = "ProcessCreate"      # Event ID 1
"Credentials" = "ProcessAccess"  # Event ID 10
"Download" = "ProcessCreate"     # Event ID 1
"ADS" = "FileCreate"             # Event ID 11
```

### Настройки Rule Group

```toml
[rule_groups]
prefix = "LOLBAS_"           # Префикс для fallback правил
cmd_prefix = "LOLBAS_CMD_"   # Префикс для CommandLine правил
unique_rules = false         # Включить дедупликацию по умолчанию
```

### Источники данных

```toml
[lolbas]
json_file = "lolbas.json"
url = "https://lolbas-project.github.io/api/lolbas.json"

[mitre]
json_file = "enterprise-attack.json"
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
```

## Формат вывода

Сгенерированные правила следуют XML-схеме Sysmon:

```xml
<?xml version='1.0' encoding='utf-8'?>
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- CommandLine правила (более специфичные) -->
    <RuleGroup name="LOLBAS_CMD_Execute" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Загрузка и выполнение удалённого XSL-скрипта -->
        <Rule groupRelation="and"
              name="technique_id=T1220,technique_name=XSL Script Processing">
          <OriginalFileName condition="is">wmic.exe</OriginalFileName>
          <CommandLine condition="contains any">/format</CommandLine>
        </Rule>
      </ProcessCreate>
    </RuleGroup>

    <!-- Fallback правила (более широкое обнаружение) -->
    <RuleGroup name="LOLBAS_Execute" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Windows Management Instrumentation Command -->
        <OriginalFileName condition="is"
              name="technique_id=T1220,technique_name=XSL Script Processing">
          wmic.exe
        </OriginalFileName>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

## Как это работает

1. **Получение данных** — Загружает JSON LOLBAS (список LOLBins с командами, категориями, маппингами MITRE) и данные MITRE ATT&CK (названия техник)

2. **Парсинг и фильтрация** — Парсит записи LOLBin и фильтрует по включённым категориям

3. **Генерация правил** — Для каждой категории:
   - Создаёт CommandLine правила (executable + специфичные флаги из примеров команд)
   - Создаёт fallback правила (только имя executable/OriginalFileName)

   > **Ограничение схемы Sysmon:** Поле CommandLine доступно только в событиях ProcessCreate. Для категорий, сопоставленных с FileCreate или ProcessAccess, генерируются только fallback правила.

4. **Обогащение MITRE** — Добавляет `technique_id` и `technique_name` в атрибуты правил

5. **Вывод** — Сохраняет standalone XML или объединяет с существующей конфигурацией Sysmon

## Анализ покрытия

Флаг `--coverage` анализирует, сколько LOLBins из проекта LOLBAS покрыто существующей конфигурацией Sysmon:

Пример вывода:
```
LOLBAS Coverage Report

Total LOLBins in LOLBAS:    227
Covered in config:          97
Missing from config:        130
Coverage:                   42.7%
```

LOLBin считается "покрытым", если его `Name` или `OriginalFileName` присутствует в любом правиле конфигурации (теги Image, OriginalFileName, SourceImage или TargetImage).

## Логика дедупликации

При включённом `--unique-rules`:

- **CMD правила**: Дедуплицируются по `(executable, event_type, flags)` — одинаковый executable с одинаковыми флагами в одном event type пропускается
- **Fallback правила**: Дедуплицируются по `(executable, event_type)` — одинаковый executable в одном event type пропускается
- CMD и fallback правила отслеживаются раздельно (CMD правило не предотвращает создание fallback правила)

## Тестирование

Запускайте тесты из корня проекта:

```bash
python -m pytest tests -v
```

Если используете Poetry:

```bash
poetry run python -m pytest tests -v
```

## Разработка

### Pre-commit хуки

Проект использует pre-commit хуки для обеспечения качества кода. Установите их:

```bash
pip install pre-commit
pre-commit install
```

Хуки автоматически запустятся при `git commit`:
- **ruff** — форматирование и линтинг кода
- **trailing-whitespace** — удаление trailing whitespace
- **end-of-file-fixer** — файлы заканчиваются переводом строки
- **check-yaml/toml** — валидация синтаксиса YAML и TOML

Запуск хуков вручную на всех файлах:

```bash
pre-commit run --all-files
```

### Continuous Integration

GitHub Actions автоматически запускается при каждом push/PR:
- Тесты на Python 3.11-3.13
- Линтинг с помощью ruff
- Проверка сборки Docker

См. `.github/workflows/ci.yml` для деталей.

## Участие в разработке

Вклад в проект приветствуется! Не стесняйтесь отправлять Pull Request.

1. Сделайте форк репозитория
2. Создайте ветку для вашей функции (`git checkout -b feature/amazing-feature`)
3. Зафиксируйте изменения (`git commit -m 'Add amazing feature'`)
4. Отправьте в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## Лицензия

Этот проект лицензирован под лицензией MIT — см. файл [LICENSE](LICENSE) для деталей.

## Благодарности

- [LOLBAS Project](https://lolbas-project.github.io/) — Living Off The Land Binaries and Scripts
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversarial Tactics, Techniques, and Common Knowledge
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) — System Monitor от Microsoft Sysinternals
- [Sysmon Modular](https://github.com/olafhartong/sysmon-modular) — Модульная конфигурация Sysmon
