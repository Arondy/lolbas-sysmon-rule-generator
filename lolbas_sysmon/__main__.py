from lolbas_sysmon.cli import CLI


def main() -> None:
    cli = CLI()
    exit(cli.run())


if __name__ == "__main__":
    main()
