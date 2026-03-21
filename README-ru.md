# LOLBAS Sysmon Rule Generator

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🌍 *Read this in other languages: [English](README.md), [Русский](README-ru.md)*

---

CLI-утилита на Python для автоматической генерации правил обнаружения Sysmon на основе данных [LOLBAS Project](https://lolbas-project.github.io/) (Living Off The Land Binaries and Scripts), обогащённых [Sigma Rules](https://github.com/SigmaHQ/sigma) и маппингом [MITRE ATT&CK](https://attack.mitre.org/).

## Обзор

LOLBAS Project документирует легитимные бинарные файлы Windows, которые могут быть использованы злоумышленниками. Этот инструмент автоматизирует создание правил Sysmon для этих бинарных файлов, комбинируя три источника данных для максимального покрытия:

1. **LOLBAS Project** — определения LOLBins с примерами команд и категориями
2. **Sigma Rules** — детекторские правила сообщества, указанные в записях LOLBAS
3. **MITRE ATT&CK** — идентификаторы и названия техник для аннотации правил

### Ключевые возможности

- **Автоматическая генерация правил** — Получает данные LOLBAS Project и генерирует XML-правила Sysmon
- **Обогащение Sigma Rules** — Загружает и парсит Sigma-правила из ссылок LOLBAS для более точных CommandLine правил (приоритет над извлечёнными флагами)
- **Несколько типов событий** — Поддержка ProcessCreate (Event ID 1), NetworkConnect (Event ID 3), ImageLoad (Event ID 7), ProcessAccess (Event ID 10) и FileCreate (Event ID 11)
- **Два типа правил**:
  - **CommandLine правила** — Более точное обнаружение с использованием executable + флагов командной строки (из Sigma или примеров команд LOLBAS)
  - **Fallback правила** — Более широкое обнаружение только по имени executable
- **Интеграция с MITRE ATT&CK** — Обогащение правил идентификаторами и названиями техник
- **Умное кэширование** — Все внешние данные (LOLBAS, MITRE, Sigma) кэшируются локально с настраиваемым автообновлением (по умолчанию: 28 дней)
- **Гибкая конфигурация** — TOML-конфигурация для категорий, маппингов и префиксов
- **Поддержка слияния** — Объединение сгенерированных правил с существующими конфигурациями Sysmon
- **Анализ покрытия** — Анализ сколько LOLBins покрыто существующей конфигурацией Sysmon
- **Дедупликация** — Опциональный флаг `--unique-rules` для пропуска дублирующихся правил между категориями
- **Детальная статистика** — Сводка обогащения Sigma с счётчиками загрузок/парсинга/пропусков

## Установка

### Требования

- Python 3.11 или выше
- pip или иной менеджер пакетов Python

### Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/Arondy/lolbas-sysmon-rule-generator.git
cd lolbas-sysmon-rule-generator
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
3. Загрузку и парсинг Sigma-правил, указанных в записях LOLBAS
4. Генерацию правил и сохранение в `lolbas_rules.xml`

### Параметры командной строки

```
usage: lolbas_sysmon [-h] [-i INPUT] [-o OUTPUT] [-f] [-c CONFIG]
                     [--category CATEGORY] [--dry-run] [--lolbas-json PATH]
                     [--mitre-json PATH] [--unique-rules] [--coverage]
                     [--show-missing] [--show-covered] [--only-cmd | --only-fallback]
                     [--update-data] [--update-lolbas] [--update-mitre]
                     [--no-sigma] [--update-sigma]

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
  --coverage            Анализ покрытия LOLBAS в существующей конфигурации Sysmon (требует -i)
  --show-missing        Показать список LOLBins, отсутствующих в конфигурации (используется с --coverage)
  --show-covered        Показать список покрытых LOLBins (используется с --coverage)
  --only-cmd            Генерировать только CommandLine правила (более специфичные)
  --only-fallback       Генерировать только fallback правила (только имя executable)
  --update-data         Принудительно перезагрузить данные LOLBAS, MITRE и Sigma
  --update-lolbas       Принудительно перезагрузить данные LOLBAS JSON
  --update-mitre        Принудительно перезагрузить данные MITRE ATT&CK JSON
  --no-sigma            Отключить обогащение на основе Sigma-правил
  --update-sigma        Принудительно перезагрузить кэшированные Sigma-правила
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

**Генерация только CommandLine правил (без fallback):**
```bash
python -m lolbas_sysmon --only-cmd
```

**Генерация только fallback правил (без CommandLine):**
```bash
python -m lolbas_sysmon --only-fallback
```

**Отключение обогащения Sigma (использовать только примеры команд LOLBAS):**
```bash
python -m lolbas_sysmon --no-sigma
```

**Принудительное обновление всех кэшированных данных:**
```bash
python -m lolbas_sysmon --update-data
```

**Принудительное обновление только Sigma-правил:**
```bash
python -m lolbas_sysmon --update-sigma
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
  "Conceal",
  "Copy",
  "Credentials",
  "Decode",
  "Download",
  "Dump",
  "Encode",
  "Execute",
  "Reconnaissance",
  "Tamper",
  "UAC Bypass",
  "Upload",
]
```

Доступные категории:
| Категория | Описание |
|----------|----------|
| ADS | Операции с Alternate Data Stream |
| AWL Bypass | Обход белых списков приложений |
| Compile | Компиляция кода |
| Conceal | Сокрытие вредоносной активности |
| Copy | Операции копирования файлов |
| Credentials | Доступ к учётным данным/дампинг |
| Decode | Декодирование закодированных payload'ов |
| Download | Загрузка файлов из интернета |
| Dump | Дампинг памяти/процессов |
| Encode | Кодирование payload'ов |
| Execute | Выполнение произвольного кода/команд |
| Reconnaissance | Перечисление системы/сети |
| Tamper | Изменение системных настроек/файлов |
| UAC Bypass | Обход User Account Control |
| Upload | Эксфильтрация данных |

### Маппинг типов событий

Сопоставление категорий с одним или несколькими типами событий Sysmon:

```toml
[mappings]
"Execute" = ["ProcessCreate", "ImageLoad"]    # Event ID 1, 7
"Download" = ["ProcessCreate", "NetworkConnect"]  # Event ID 1, 3
"Credentials" = ["ProcessAccess"]             # Event ID 10
"ADS" = ["FileCreate"]                        # Event ID 11
"Dump" = ["ProcessAccess", "ImageLoad"]       # Event ID 10, 7
```

> **Примечание:** Правила ImageLoad генерируются только для LOLBins с расширением `.dll`.

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
auto_update = true
max_age_days = 28

[mitre]
json_file = "enterprise-attack.json"
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
auto_update = true
max_age_days = 28
```

### Конфигурация Sigma

```toml
[sigma]
enabled = true
cache_dir = "cache_sigma_rules"
auto_update = true
max_age_days = 28
```

## Формат вывода

Сгенерированные правила следуют XML-схеме Sysmon:

```xml
<?xml version='1.0' encoding='utf-8'?>
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- CommandLine правила (более специфичные, обогащённые Sigma) -->
    <RuleGroup name="LOLBAS_CMD_Execute" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Sigma: Suspicious Certutil Command Usage | Level: high | ID: e011a729-... -->
        <Rule groupRelation="and"
              name="technique_id=T1027,technique_name=Obfuscated Files or Information">
          <OriginalFileName condition="is">CertUtil.exe</OriginalFileName>
          <CommandLine condition="contains any">-decode;-decodehex;-urlcache;-encode</CommandLine>
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

2. **Обогащение Sigma** — Загружает Sigma-правила, указанные в записях LOLBAS, парсит блоки обнаружения и выражения условий, прикрепляет конвертируемые правила к LOLBins

3. **Парсинг и фильтрация** — Парсит записи LOLBin и фильтрует по включённым категориям

4. **Генерация правил** — Для каждой категории и типа события:
   - Создаёт CommandLine правила, используя Sigma-правила (приоритет) или флаги из команд LOLBAS (запасной вариант)
   - Создаёт fallback правила (только имя executable/OriginalFileName)
   - Правила ImageLoad генерируются только для `.dll` LOLBins

   > **Ограничение схемы Sysmon:** Поле CommandLine доступно только в событиях ProcessCreate. Для категорий, сопоставленных с FileCreate, ProcessAccess, NetworkConnect или ImageLoad, генерируются только fallback правила.

5. **Обогащение MITRE** — Добавляет `technique_id` и `technique_name` в атрибуты правил

6. **Вывод** — Сохраняет standalone XML или объединяет с существующей конфигурацией Sysmon

### Детали обогащения Sigma

Инструмент загружает Sigma YAML-файлы по URL-адресам из секции `Detection` записей LOLBAS, конвертирует GitHub blob URL в raw content URL и парсит их с помощью [pySigma](https://github.com/SigmaHQ/pySigma). Поддерживаемые возможности Sigma:

- **Категории logsource**: `process_creation`, `file_event`, `network_connection`, `image_load`, `process_access`, `registry_event`
- **Логика условий**: `and`, `or`, `not`, `1 of selection_*`, `all of selection_*`, выражения в скобках
- **Модификаторы полей**: `contains`, `startswith`, `endswith`, `contains|all`, `contains|any`

После обогащения выводится детальная сводка статистики:

```
Sigma enrichment summary:
  URLs: 292 total, 258 downloaded, 34 cached, 0 failed
  Rules: 254 parsed, 231 convertible
  Skipped: 15 (unsupported fields), 8 (unsupported features)
  LOLBins enriched: 176
  Top skip reasons: feature:re: 8, field:Initiated: 4, field:Description: 3
```

## Анализ покрытия

Флаг `--coverage` анализирует, сколько LOLBins из проекта LOLBAS покрыто существующей конфигурацией Sysmon:

Пример вывода:
```
LOLBAS Coverage Report

Total LOLBins in LOLBAS:    227
Covered in config:          97
Missing from config:        130
Coverage:                   42.7%
CMD Rules:                  85
Fallback rules:             97
```

LOLBin считается "покрытым", если его `Name` или `OriginalFileName` присутствует в любом правиле конфигурации (теги Image, OriginalFileName, SourceImage, TargetImage или ImageLoaded).

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
- [Sigma Rules](https://github.com/SigmaHQ/sigma) — Generic Signature Format for SIEM Systems
- [pySigma](https://github.com/SigmaHQ/pySigma) — Python-библиотека для обработки Sigma-правил
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversarial Tactics, Techniques, and Common Knowledge
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) — System Monitor от Microsoft Sysinternals
- [Sysmon Modular](https://github.com/olafhartong/sysmon-modular) — Модульная конфигурация Sysmon
