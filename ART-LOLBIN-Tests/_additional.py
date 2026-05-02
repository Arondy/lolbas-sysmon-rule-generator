import json


def load_allowed_tests(config_path):
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    allowed = set()

    for item in config['tests']:
        tid = item['technique_id']

        for num in item['test_numbers']:
            allowed.add((tid, num))

    return allowed


def filter_cases(data, allowed_tests):
    original_count = len(data['cases'])
    data['cases'] = [c for c in data['cases'] if (c['technique_id'], c['test_number']) in allowed_tests]
    removed = original_count - len(data['cases'])
    return data, removed


def update_summary(data):
    cases = data['cases']
    data['summary']['cases_total'] = len(cases)
    data['summary']['cases_completed'] = len(cases)
    data['summary']['cases_error'] = sum(1 for c in cases if c.get('status') == 'error')

    tp = sum(1 for c in cases if c.get('tp') == 1)
    data['summary']['tp'] = tp
    data['summary']['tp_precise'] = sum(1 for c in cases if c.get('tp_precise') == 1)
    data['summary']['tp_regular'] = sum(1 for c in cases if c.get('tp_regular') == 1)

    fn = sum(1 for c in cases if c.get('fn') == 1)
    data['summary']['fn'] = fn
    data['summary']['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0
    return data


def process_file(file_path, allowed_tests):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    data, removed = filter_cases(data, allowed_tests)

    if 'summary' in data:
        data = update_summary(data)

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return len(data['cases']), removed


def count_average(file_path):
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)

    counts = [case["sysmon_events_count"] for case in data["cases"] if "sysmon_events_count" in case]
    average = sum(counts) / len(counts) if counts else 0

    return average


if __name__ == "__main__":
    config_path = 'configs/final_config.json'
    allowed_tests = load_allowed_tests(config_path)
    print(f'Разрешенных тестов в {config_path}: {len(allowed_tests)}')

    for file_path in ['test_results/olaf.json', 'test_results/enriched.json']:
        remaining, removed = process_file(file_path, allowed_tests)
        print(f'{file_path}: удалено {removed} запусков, осталось {remaining}')

        average = count_average(file_path)
        print(f'{file_path}: среднее значение sysmon_events_count: {average}')
