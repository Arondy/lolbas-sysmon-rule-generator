# ART-LOLBIN-Tests

Тестирование детектирования LOLBin атак с использованием Atomic Red Team и Sysmon.

## Описание

Проект предназначен для автоматизированного тестирования правил Sysmon на способность детектировать атаки через легитимные инструменты Windows. Использует сценарии из базы Atomic Red Team.

## Структура

- `AtomicRedTeam_LOLBIN_TESTS.ps1` — подготовка окружения, скачивание Atomic Red Team, выбор LOLBin-техник и генерация конфигурации

- `main.py` — запуск тестов и сбор результатов

- `test_runner/` — модуль для выполнения тестов:

- `_additional.py` — утилиты для обработки и фильтрации результатов

- `configs/` — файлы конфигурации:
  - `config_example.json` — пример конфигурационного файла
  - `config_generated.json` — автоматически сгенерированная конфигурация по техникам в `.ps1` файле
  - `final_config.json` — финальная конфигурация с отобранными тестами

- `test_results/` — результаты выполнения тестов:
  - `sysmon-modular.json` — результаты тестирования с sysmon-modular
  - `enriched.json` — результаты тестирования с sysmon-modular-enriched

## Требования

- Windows 10+
- Python 3.8+
- PowerShell 5.1+
- Sysmon с настроенными правилами
- Установленный модуль PowerShell: `Invoke-AtomicRedTeam` (устанавливается через `.ps1` файл)

## Установка

```bash
pip install -r requirements.txt
```

## Использование

### 1. Подготовка в PowerShell

```powershell
.\AtomicRedTeam_LOLBIN_TESTS.ps1
```

Скрипт выполнит:
- Скачивание репозитория Atomic Red Team
- Поиск техник, связанных с LOLBin
- Генерацию конфигурационного файла `ART_lolbin_tests/config_generated.json`

Для просмотра списка техник без запуска:

```powershell
.\AtomicRedTeam_LOLBIN_TESTS.ps1 -ListOnly
```

### 2. Запуск тестов

```bash
python main.py --config ART_lolbin_tests/config_generated.json --output test_results/results.json
```

Сохранение промежуточных результатов и дополнение при добавлении новых тестов:

```bash
python main.py --config ART_lolbin_tests/config_generated.json --output test_results/results.json --save
```

## Как это работает

1. Вокруг запуска каждого Atomic-теста расставляются маркеры
2. После выполнения теста собираются события Sysmon в окне между маркерами
3. Анализируются RuleName событий на соответствие технике MITRE ATT&CK
4. Формируется статистика: TP, FN, полнота детектирования

## Результаты

Результаты сохраняются в JSON-формате и содержат:
- Общую статистику с TP, FN, полнотой
- Детализацию по каждому тесту
- Количество событий Sysmon
- Список сработавших правил
