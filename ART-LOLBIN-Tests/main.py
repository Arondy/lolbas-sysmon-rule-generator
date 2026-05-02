import argparse
import sys

from test_runner.config_loader import load_config
from test_runner.orchestrator import run_benchmark


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", required=True, help="Путь к JSON конфигурации")
    parser.add_argument("--output", "-o", required=False, help="Путь к итоговому JSON результату")
    parser.add_argument("--save", "-s", action="store_true", help="Режим сохранения с возможностью дозаписи")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        config = load_config(args.config, args.output)
        run_benchmark(config, save_mode=args.save)
        return 0
    except Exception as exc:
        print(f"[!] Ошибка запуска: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
