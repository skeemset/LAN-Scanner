import sys

_DEPS_HINT = (
    "Не хватает зависимостей.\n"
    "Если ставили их в venv, а запускаете через sudo, укажите python из venv:\n"
    "    sudo .venv/bin/python -m lanscan\n"
    "Либо установите зависимости в активное окружение:\n"
    "    pip install -r requirements.txt\n"
)


def main():
    try:
        from . import cli
    except ImportError as error:
        sys.stderr.write(_DEPS_HINT + f"Подробнее: {error}\n")
        return 1

    result = cli.run()
    if result is not None:
        return result

    try:
        from .ui import App
    except ImportError as error:
        sys.stderr.write(_DEPS_HINT + f"Подробнее: {error}\n")
        return 1

    try:
        App().run()
    except KeyboardInterrupt:
        sys.stderr.write("\nПрервано пользователем.\n")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
